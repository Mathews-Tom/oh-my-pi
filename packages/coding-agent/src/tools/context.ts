import type { AgentToolContext, ToolCallContext } from "@oh-my-pi/pi-agent-core";
import type { CustomToolContext } from "../extensibility/custom-tools/types";
import type { ExtensionUIContext } from "../extensibility/extensions/types";

declare module "@oh-my-pi/pi-agent-core" {
	interface AgentToolContext extends CustomToolContext {
		ui?: ExtensionUIContext;
		hasUI?: boolean;
		toolNames?: string[];
		toolCall?: ToolCallContext;
		/** Set on `xd://` device dispatches: the write tool's outer approval gate
		 *  already resolved this call at the mounted tool's tier, so the inner
		 *  wrapper must not re-prompt for the same action (explicit per-tool
		 *  policies and overrides still apply). */
		xdevApproved?: boolean;
		/** Set only after an interactive prompt approves provider computer safety checks. */
		providerSafetyApproved?: boolean;
		/**
		 * Rollback handle for staged previews (`queueResolveHandler`), so a
		 * post-execution denial can drop an apply closure the denied call
		 * registered mid-execution. Absent outside a live session, where there is
		 * no tool-choice queue and so nothing to stage.
		 */
		pendingPreviews?: PendingPreviewRollback;
	}
}

/** Narrow view of the tool-choice queue's staged-preview registry. See `AgentToolContext.pendingPreviews`. */
export interface PendingPreviewRollback {
	/** Id of the currently staged head, or `undefined` when nothing is staged. */
	headId(): string | undefined;
	/** Drop every preview staged after `id` — see `ToolChoiceQueue.removePendingInvokersSince`. */
	removeSince(id: string | undefined): void;
}

export class ToolContextStore {
	#uiContext: ExtensionUIContext | undefined;
	#hasUI = false;
	#toolNames: string[] = [];

	constructor(
		private readonly getBaseContext: () => CustomToolContext & { pendingPreviews?: PendingPreviewRollback },
	) {}

	getContext(toolCall?: ToolCallContext): AgentToolContext {
		return {
			...this.getBaseContext(),
			ui: this.#uiContext,
			hasUI: this.#hasUI,
			toolNames: this.#toolNames,
			toolCall,
		};
	}

	setUIContext(uiContext: ExtensionUIContext, hasUI: boolean): void {
		this.#uiContext = uiContext;
		this.#hasUI = hasUI;
	}

	setToolNames(names: string[]): void {
		this.#toolNames = names;
	}
}
