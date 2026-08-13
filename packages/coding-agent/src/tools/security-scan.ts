import * as path from "node:path";
import { type } from "@oh-my-pi/omptype";
import type {
	AgentTool,
	AgentToolContext,
	AgentToolResult,
	AgentToolUpdateCallback,
	ToolTier,
} from "@oh-my-pi/pi-agent-core";
import securityScanDescription from "../prompts/tools/security-scan.md" with { type: "text" };
import { selectSecurityAccount } from "../security/auth";
import {
	CodexSecurityCloudClient,
	type CodexSecurityCloudConfiguration,
	type CodexSecurityCloudStats,
	pullCodexSecurityCloudResults,
} from "../security/cloud";
import { createSecurityEvidenceId, type SecurityEvidence, type SecurityValidationStatus } from "../security/contracts";
import type { SecurityOperationSnapshot } from "../security/coordinator";
import { getSecurityCoordinator } from "../security/coordinator";
import type { SecurityScanGuard, SecurityTargetRequest } from "../security/preflight";
import { resolveSecurityProjectDirectoryForCwd, SecurityStore } from "../security/store";
import type { ToolSession } from "./index";
import { enforceResourcePathTargets } from "./permissions/gate";
import { ToolError } from "./tool-errors";

const securityScanSchema = type({
	action:
		"'preflight' | 'start' | 'status' | 'cancel' | 'validate' | 'cloud_scans' | 'cloud_start' | 'cloud_status' | 'cloud_pull'",
	"plan_id?": "string",
	"operation_id?": "string",
	"target_kind?": "'repository' | 'scoped_path' | 'ref_diff' | 'working_tree'",
	"include_paths?": "string[]",
	"exclude_paths?": "string[]",
	"base_revision?": "string",
	"head_revision?": "string",
	"knowledge_base_paths?": "string[]",
	"output_root?": "string",
	"archive_existing?": "boolean",
	"credential_id?": "number.integer >= 1",
	"scan_id?": "string",
	"finding_id?": "string",
	"validation_status?": "'unvalidated' | 'validated' | 'rejected' | 'partial' | 'error'",
	"validation_summary?": "string",
	"validation_evidence?": type({ label: "string > 0", explanation: "string" }).array(),
	"cloud_configuration_id?": "string",
	"repository_id?": "string",
	"repository_url?": "string",
	"environment_id?": "string",
	"lookback_days?": "number.integer >= 1 | 'all'",
});

type SecurityScanParams = typeof securityScanSchema.infer;

export interface SecurityScanToolDetails {
	action: SecurityScanParams["action"];
	plan?: { id: string; fingerprint: string };
	operation?: SecurityOperationSnapshot;
	cancelled?: boolean;
	finding?: { id: string; validationStatus: SecurityValidationStatus };
	cloudConfigurations?: CodexSecurityCloudConfiguration[];
	cloudStats?: CodexSecurityCloudStats;
	cloudScan?: { id: string; repositoryUrl: string };
	importedScan?: { id: string; findingCount: number };
}

/**
 * Resource-permission hooks for the scan surfaces the tool's own arguments
 * never name.
 *
 * `TOOL_PATH_CLASSES.security_scan` can only extract what the call declares —
 * `include_paths`, `knowledge_base_paths`, `output_root`. A default
 * `target_kind: "repository"` scan declares no read path at all yet hashes and
 * reviews every tracked and untracked in-scope file, and an omitted
 * `output_root` is defaulted deep inside the coordinator. The `SecurityStore`
 * project directory is never named at all — it is derived from `cwd` and
 * opened (creating state on disk) before the plan is built. All three are
 * resolved mid-preflight, so this is the only layer that holds the session
 * context *and* runs late enough to see the effective values.
 *
 * Returns `undefined` when there is no context to measure against, matching how
 * every other gate entry point behaves outside a live session.
 */
function resourcePermissionGuard(context: AgentToolContext | undefined): SecurityScanGuard | undefined {
	if (!context) return undefined;
	return {
		scope: (relativePaths, repositoryRoot) => {
			enforceResourcePathTargets(
				"security_scan",
				relativePaths.map(relativePath => ({
					raw: path.resolve(repositoryRoot, relativePath),
					access: "read" as const,
					field: "scan scope",
				})),
				context,
			);
		},
		knowledgeBase: absolutePath => {
			enforceResourcePathTargets(
				"security_scan",
				[{ raw: absolutePath, access: "read", field: "knowledge_base_paths" }],
				context,
			);
		},
		outputRoot: absolutePath => {
			enforceResourcePathTargets(
				"security_scan",
				[{ raw: absolutePath, access: "write" as const, field: "output_root" }],
				context,
			);
		},
		stateDirectory: absolutePath => {
			enforceResourcePathTargets(
				"security_scan",
				[
					{ raw: absolutePath, access: "read" as const, field: "state directory" },
					{ raw: absolutePath, access: "write" as const, field: "state directory" },
				],
				context,
			);
		},
	};
}

/**
 * Open the `SecurityStore` for `cwd`, authorizing the resolved project state
 * directory first. `cloud_pull` and `validate` open the store directly
 * (there is no `SecurityCoordinator` action for either), so each needs this
 * same pre-open gate `SecurityCoordinator#gateStateDirectory` runs for
 * `preflight`/`start` — otherwise a plan saved while permissions were off,
 * then `workspace` enabled before one of these actions, would mutate the
 * state store unauthorized.
 */
async function openGatedSecurityStore(
	cwd: string,
	guard: SecurityScanGuard | undefined,
	signal?: AbortSignal,
): Promise<SecurityStore> {
	const { projectDirectory } = await resolveSecurityProjectDirectoryForCwd(cwd, { signal });
	guard?.stateDirectory?.(projectDirectory);
	return SecurityStore.openForCwd(cwd, { signal });
}

function targetFromParams(params: SecurityScanParams): SecurityTargetRequest {
	const common = { includePaths: params.include_paths, excludePaths: params.exclude_paths };
	switch (params.target_kind ?? "repository") {
		case "scoped_path": {
			if (!params.include_paths?.some(value => value.trim().length > 0)) {
				throw new ToolError("scoped_path security scans require at least one include path");
			}
			return { kind: "scoped_path", includePaths: params.include_paths, excludePaths: params.exclude_paths };
		}
		case "working_tree":
			return { kind: "working_tree", ...common };
		case "ref_diff":
			if (!params.base_revision || !params.head_revision) {
				throw new ToolError("ref_diff preflight requires base_revision and head_revision");
			}
			return {
				kind: "ref_diff",
				baseRevision: params.base_revision,
				headRevision: params.head_revision,
				...common,
			};
		default:
			return { kind: "repository", ...common };
	}
}

function requireValue(value: string | undefined, label: string): string {
	if (!value?.trim()) throw new ToolError(`${label} is required for this action`);
	return value.trim();
}

function cloudClientForSession(session: ToolSession, credentialId?: number): CodexSecurityCloudClient {
	if (!session.authStorage) throw new ToolError("Codex Security cloud requires the authentication registry");
	const account = selectSecurityAccount(
		session.authStorage,
		"openai-codex",
		credentialId,
		session.getSessionId?.() ?? undefined,
	);
	return new CodexSecurityCloudClient({ authStorage: session.authStorage, account });
}

function textResult(text: string, details: SecurityScanToolDetails): AgentToolResult<SecurityScanToolDetails> {
	return { content: [{ type: "text", text }], details };
}

export class SecurityScanTool implements AgentTool<typeof securityScanSchema, SecurityScanToolDetails> {
	readonly name = "security_scan";
	readonly approval: ToolTier = "exec";
	readonly label = "Security Scan";
	readonly loadMode = "discoverable";
	readonly summary = "Run OMP-native scans and explicit Codex Security cloud operations";
	readonly description = securityScanDescription.trim();
	readonly parameters = securityScanSchema;
	readonly strict = true;

	constructor(readonly session: ToolSession) {}

	async execute(
		_toolCallId: string,
		params: SecurityScanParams,
		signal?: AbortSignal,
		_onUpdate?: AgentToolUpdateCallback<SecurityScanToolDetails>,
		context?: AgentToolContext,
	): Promise<AgentToolResult<SecurityScanToolDetails>> {
		if (!this.session.settings.get("security.enabled")) {
			throw new ToolError("Security is disabled. Enable security.enabled before using security_scan.");
		}
		const coordinatorForSession = () => {
			if (!this.session.modelRegistry || !this.session.authStorage) {
				throw new ToolError("Security scan requires the session model and authentication registries");
			}
			return getSecurityCoordinator({
				cwd: this.session.cwd,
				settings: this.session.settings,
				authStorage: this.session.authStorage,
				modelRegistry: this.session.modelRegistry,
				activeModel: this.session.getActiveModel?.(),
				sessionId: this.session.getSessionId?.() ?? undefined,
				agentId: this.session.getAgentId?.() ?? undefined,
				asyncJobManager: this.session.asyncJobManager,
			});
		};
		switch (params.action) {
			case "preflight": {
				const model = this.session.getActiveModel?.();
				const plan = await coordinatorForSession().preflight({
					target: targetFromParams(params),
					knowledgeBasePaths: params.knowledge_base_paths,
					outputRoot: params.output_root,
					archiveExisting: params.archive_existing,
					credentialId: params.credential_id,
					model,
					signal,
					guard: resourcePermissionGuard(context),
				});
				return textResult(
					[
						`Security plan ${plan.id} is ready.`,
						`Fingerprint: ${plan.fingerprint}.`,
						`Start it with action=start and plan_id=${plan.id}.`,
					].join(" "),
					{ action: params.action, plan: { id: plan.id, fingerprint: plan.fingerprint } },
				);
			}
			case "start": {
				const operation = await coordinatorForSession().start({
					planId: requireValue(params.plan_id, "plan_id"),
					guard: resourcePermissionGuard(context),
				});
				return textResult(`Security scan ${operation.scanId} started as ${operation.operationId}.`, {
					action: params.action,
					operation,
				});
			}
			case "status": {
				const operationId = requireValue(params.operation_id, "operation_id");
				const operation = await coordinatorForSession().status(operationId, resourcePermissionGuard(context));
				if (!operation) throw new ToolError(`Unknown security operation: ${operationId}`);
				return textResult(
					`Security scan ${operation.scanId}: ${operation.phase}; ${operation.findingCount} finding(s).`,
					{ action: params.action, operation },
				);
			}
			case "cancel": {
				const operationId = requireValue(params.operation_id, "operation_id");
				const guard = resourcePermissionGuard(context);
				const cancelled = await coordinatorForSession().cancel(operationId, guard);
				return textResult(
					cancelled ? `Cancellation requested for ${operationId}.` : `No running operation ${operationId}.`,
					{
						action: params.action,
						cancelled,
						operation: (await coordinatorForSession().status(operationId, guard)) ?? undefined,
					},
				);
			}
			case "cloud_scans": {
				const configurations = await cloudClientForSession(
					this.session,
					params.credential_id,
				).listAllConfigurations(signal);
				return textResult(
					configurations.length === 0
						? "No Codex Security cloud scan configurations are available."
						: configurations
								.map(
									item =>
										`${item.id} ${item.currentStep ?? "unknown"} repo=${item.repositoryId} environment=${item.environmentId} ${item.repositoryUrl}`,
								)
								.join("\n"),
					{ action: params.action, cloudConfigurations: configurations },
				);
			}
			case "cloud_start": {
				const configuration = await cloudClientForSession(this.session, params.credential_id).startScan({
					repositoryId: requireValue(params.repository_id, "repository_id"),
					repositoryUrl: requireValue(params.repository_url, "repository_url"),
					environmentId: requireValue(params.environment_id, "environment_id"),
					lookbackDays: params.lookback_days,
					signal,
				});
				return textResult(
					`Codex Security cloud scan ${configuration.id} started for ${configuration.repositoryUrl}. This consumes cloud scan allowance.`,
					{
						action: params.action,
						cloudScan: { id: configuration.id, repositoryUrl: configuration.repositoryUrl },
					},
				);
			}
			case "cloud_status": {
				const stats = await cloudClientForSession(this.session, params.credential_id).getStats(
					requireValue(params.cloud_configuration_id, "cloud_configuration_id"),
					signal,
				);
				return textResult(
					`Codex Security cloud scan ${stats.configurationId}: ${stats.currentStep ?? "unknown"}; ${stats.finishedCommits} finished commit(s), ${stats.pendingCommits} pending.`,
					{ action: params.action, cloudStats: stats },
				);
			}
			case "cloud_pull": {
				const store = await openGatedSecurityStore(this.session.cwd, resourcePermissionGuard(context), signal);
				const bundle = await pullCodexSecurityCloudResults({
					client: cloudClientForSession(this.session, params.credential_id),
					configurationId: requireValue(params.cloud_configuration_id, "cloud_configuration_id"),
					store,
					signal,
				});
				return textResult(
					`Imported ${bundle.findings.length} Codex Security cloud finding(s) as security scan ${bundle.scan.id}.`,
					{
						action: params.action,
						importedScan: { id: bundle.scan.id, findingCount: bundle.findings.length },
					},
				);
			}
			case "validate": {
				const scanId = requireValue(params.scan_id, "scan_id");
				const findingId = requireValue(params.finding_id, "finding_id");
				const status = params.validation_status;
				if (!status) throw new ToolError("validation_status is required for this action");
				const summary = requireValue(params.validation_summary, "validation_summary");
				const store = await openGatedSecurityStore(this.session.cwd, resourcePermissionGuard(context), signal);
				const finding = await store.getFinding(scanId, findingId);
				if (!finding) throw new ToolError(`Unknown security finding: ${findingId}`);
				const evidence: SecurityEvidence[] = (params.validation_evidence ?? []).map((item, index) => ({
					id: createSecurityEvidenceId(
						finding.fingerprint,
						`validation:${item.label}`,
						finding.evidence.length + index,
					),
					kind: "validation",
					label: item.label,
					explanation: item.explanation,
				}));
				const updated = await store.updateValidation(
					scanId,
					findingId,
					{
						status,
						summary,
						evidenceIds: evidence.map(item => item.id),
						validatedAt: new Date().toISOString(),
					},
					evidence,
				);
				return textResult(`Finding ${updated.id} validation is now ${updated.validation.status}.`, {
					action: params.action,
					finding: { id: updated.id, validationStatus: updated.validation.status },
				});
			}
		}
	}
}
