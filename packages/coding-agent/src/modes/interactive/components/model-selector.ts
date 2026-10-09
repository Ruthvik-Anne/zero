import { type Model, modelsAreEqual } from "@zero-agent/ai";
import {
	type Component,
	Container,
	type Focusable,
	fuzzyFilterScored,
	getKeybindings,
	Spacer,
	Text,
	TruncatedText,
	type TUI,
} from "@zero-agent/tui";
import type { ModelRegistry } from "../../../core/model-registry.js";
import { BUILT_IN_PROVIDER_DISPLAY_NAMES } from "../../../core/provider-display-names.js";
import { theme } from "../theme/theme.js";
import { keyHint } from "./keybinding-hints.js";
import {
	getMenuListLayout,
	MenuList,
	MenuPanel,
	MenuRow,
	MenuSearchInput,
	type MenuViewportProvider,
} from "./menu-panel.js";
import { shouldTreatAsBack } from "./modal-back.js";

interface ModelItem {
	provider: string;
	id: string;
	model: Model<any>;
}

interface ScopedModelItem {
	model: Model<any>;
	thinkingLevel?: string;
}

export interface ModelSelectorOptions {
	availableModels?: ReadonlyArray<Model<any>>;
	configuredProviders?: ReadonlySet<string>;
	header?: Component;
	getHeaderRows?: () => number;
	subtitle?: string;
	getRows?: () => number;
	recentModels?: ReadonlyArray<string>;
}

type ModelScope = "all" | "scoped";

const PREFERRED_VISIBLE_MODELS = 10;
const MODEL_LIST_RESERVED_ROWS = {
	base: 7,
	detail: 2,
};
const MODEL_SCROLL_INDICATOR_ROWS = 1;
const MODEL_HELP_MIN_ROWS = 12;
const MODEL_DETAIL_MIN_ROWS = 14;

/**
 * Component that renders a model selector with search
 */
export class ModelSelectorComponent extends Container implements Focusable {
	private searchInput: MenuSearchInput;

	// Focusable implementation - propagate to searchInput for IME cursor positioning
	private _focused = false;
	get focused(): boolean {
		return this._focused;
	}
	set focused(value: boolean) {
		this._focused = value;
		this.searchInput.focused = value;
	}
	private listContainer: Container;
	private allModels: ModelItem[] = [];
	private scopedModelItems: ModelItem[] = [];
	private activeModels: ModelItem[] = [];
	private filteredModels: ModelItem[] = [];
	private selectedIndex: number = 0;
	private searchQuery = "";
	private provider?: string;
	private providerItems: ModelItem[][] = [];
	private providerModels = new Map<string, ModelItem[]>();
	private providerInfo = new Map<string, { configured: boolean; current: boolean }>();
	private currentModel?: Model<any>;
	private modelRegistry: ModelRegistry;
	private onSelectCallback: (model: Model<any>) => void;
	private onCancelCallback: () => void;
	private availableModels?: ReadonlyArray<Model<any>>;
	private configuredProviders?: ReadonlySet<string>;
	private recentRank: Map<string, number>;
	private errorMessage?: string;
	private tui: TUI;
	private scopedModels: ReadonlyArray<ScopedModelItem>;
	private scope: ModelScope = "all";
	private scopeText?: Text;
	private scopeHintText?: Text;
	private panel: MenuPanel;
	private headerHelpContainer: Container;
	private warningText?: Text;
	private listLayout = getMenuListLayout({
		preferredVisibleItems: PREFERRED_VISIBLE_MODELS,
		reservedRows: MODEL_LIST_RESERVED_ROWS.base,
		comfortableItemRows: 3,
		compactItemRows: 2,
	});
	private responsiveLayoutKey = "";
	private readonly viewport: MenuViewportProvider;
	private readonly getHeaderRows: () => number;

	constructor(
		tui: TUI,
		currentModel: Model<any> | undefined,
		modelRegistry: ModelRegistry,
		scopedModels: ReadonlyArray<ScopedModelItem>,
		onSelect: (model: Model<any>) => void,
		onCancel: () => void,
		initialSearchInput?: string,
		options: ModelSelectorOptions = {},
	) {
		super();

		this.tui = tui;
		this.currentModel = currentModel;
		this.modelRegistry = modelRegistry;
		this.scopedModels = scopedModels;
		this.scope = scopedModels.length > 0 ? "scoped" : "all";
		this.onSelectCallback = onSelect;
		this.onCancelCallback = onCancel;
		this.availableModels = options.availableModels;
		this.configuredProviders = options.configuredProviders;
		this.recentRank = new Map((options.recentModels ?? []).map((key, i) => [key, i]));
		this.viewport = { getRows: options.getRows };
		this.getHeaderRows = options.header ? (options.getHeaderRows ?? (() => 2)) : () => 0;

		this.panel = new MenuPanel({
			title: this.isProviderView() ? "Zero · Select provider" : "Zero · Select model",
			subtitle: options.subtitle ?? "Browse providers or type to search models.",
		});
		this.addChild(this.panel);
		if (options.header) {
			this.panel.addChild(options.header);
			this.panel.addChild(new Spacer(1));
		}

		// Add hint about model filtering
		if (scopedModels.length > 0) {
			this.scopeText = new Text(this.getScopeText(), 0, 0);
			this.scopeHintText = new Text(this.getScopeHintText(), 0, 0);
		} else {
			const hintText = "Signed-in providers first. Other models prompt sign-in.";
			this.warningText = new Text(theme.fg("muted", hintText), 0, 0);
		}
		this.headerHelpContainer = new Container();
		this.panel.addChild(this.headerHelpContainer);

		// Create search input
		this.searchInput = new MenuSearchInput("Search models");
		if (initialSearchInput) {
			this.searchInput.setValue(initialSearchInput);
		}
		this.searchInput.onSubmit = () => {
			this.handleConfirm();
		};
		this.panel.addChild(this.searchInput);

		this.panel.addChild(new Spacer(1));

		// Create list container
		this.listContainer = new MenuList({ compact: true });
		this.panel.addChild(this.listContainer);
		this.updateResponsiveLayout();

		this.loadModels();
		if (initialSearchInput) {
			this.filterModels(initialSearchInput);
		} else {
			this.updateList();
		}
		this.tui.requestRender();
	}

	updateAvailableModels(availableModels: ReadonlyArray<Model<any>>): void {
		this.updateState(this.currentModel, availableModels);
	}

	updateState(
		currentModel: Model<any> | undefined,
		availableModels = this.availableModels,
		configuredProviders = this.configuredProviders,
	): void {
		this.currentModel = currentModel;
		this.availableModels = availableModels;
		this.configuredProviders = configuredProviders;
		const query = this.searchInput.getValue();
		const selectedProvider = this.isProviderView() ? this.providerItems[this.selectedIndex]?.[0].provider : undefined;
		const selectedKey = this.isProviderView() ? undefined : this.getSelectedModelKey();

		this.loadModels();
		this.filterModels(query);

		if (selectedProvider && this.isProviderView()) {
			this.selectedIndex = Math.max(
				0,
				this.providerItems.findIndex((group) => group[0].provider === selectedProvider),
			);
			this.updateList();
		}
		if (selectedKey) {
			const selectedIndex = this.filteredModels.findIndex((item) => this.getModelKey(item) === selectedKey);
			if (selectedIndex >= 0) {
				this.selectedIndex = selectedIndex;
				this.updateList();
			}
		}

		this.tui.requestRender();
	}

	private loadModels(): void {
		let models: ModelItem[];
		this.errorMessage = undefined;

		if (this.availableModels === undefined) {
			this.modelRegistry.refresh();
			const loadError = this.modelRegistry.getError();
			if (loadError) {
				this.errorMessage = loadError;
			}
		}

		// Load available models (built-in models still work even if models.json failed)
		let availableModels: ReadonlyArray<Model<any>>;
		try {
			availableModels =
				this.availableModels !== undefined ? this.availableModels : this.modelRegistry.getAvailable();
			models = availableModels.map((model: Model<any>) => ({
				provider: model.provider,
				id: model.id,
				model,
			}));
		} catch (error) {
			this.allModels = [];
			this.scopedModelItems = [];
			this.activeModels = [];
			this.filteredModels = [];
			this.providerItems = [];
			this.errorMessage = error instanceof Error ? error.message : String(error);
			return;
		}

		this.allModels = this.sortModels(models);
		const availableModelsById = new Map(availableModels.map((model) => [`${model.provider}/${model.id}`, model]));
		this.scopedModels = this.scopedModels.map((scoped) => {
			const scopedModelId = `${scoped.model.provider}/${scoped.model.id}`;
			const refreshed =
				availableModelsById.get(scopedModelId) ??
				(this.availableModels !== undefined
					? undefined
					: this.modelRegistry.find(scoped.model.provider, scoped.model.id));
			return refreshed ? { ...scoped, model: refreshed } : scoped;
		});
		this.scopedModelItems = this.scopedModels.map((scoped) => ({
			provider: scoped.model.provider,
			id: scoped.model.id,
			model: scoped.model,
		}));
		this.activeModels = this.scope === "scoped" ? this.scopedModelItems : this.allModels;
		this.refreshProviders();
		this.filteredModels = this.activeModels;
		const currentIndex = this.filteredModels.findIndex((item) => modelsAreEqual(this.currentModel, item.model));
		this.selectedIndex = this.isProviderView()
			? 0
			: currentIndex >= 0
				? currentIndex
				: Math.min(this.selectedIndex, Math.max(0, this.getSelectableCount() - 1));
	}

	private isProviderView(): boolean {
		return (
			this.provider === undefined && !this.errorMessage && !this.searchQuery.trim() && this.providerItems.length > 1
		);
	}

	private refreshProviders(): void {
		const groups = new Map<string, ModelItem[]>();
		this.providerInfo.clear();
		for (const item of this.activeModels) {
			const group = groups.get(item.provider) ?? [];
			group.push(item);
			groups.set(item.provider, group);
			const info = this.providerInfo.get(item.provider) ?? { configured: false, current: false };
			info.configured ||= this.isProviderConfigured(item);
			info.current ||= modelsAreEqual(this.currentModel, item.model);
			this.providerInfo.set(item.provider, info);
		}
		this.providerModels = groups;
		this.providerItems = [...groups.values()];
		if (this.provider && !groups.has(this.provider)) this.provider = undefined;
	}

	private getModelKey(item: ModelItem): string {
		return `${item.provider}/${item.id}`;
	}

	private getSelectedModelKey(): string | undefined {
		const selected = this.filteredModels[this.selectedIndex];
		return selected ? this.getModelKey(selected) : undefined;
	}

	private recentRankOf(item: ModelItem): number {
		// Finite sentinel so subtracting two non-recent ranks yields 0, not NaN.
		return this.recentRank.get(`${item.provider}/${item.id}`) ?? Number.MAX_SAFE_INTEGER;
	}

	private isProviderConfigured(item: ModelItem): boolean {
		return this.configuredProviders?.has(item.provider) || this.modelRegistry.hasConfiguredAuth(item.model);
	}

	private sortModels(models: ModelItem[]): ModelItem[] {
		const sorted = [...models];
		sorted.sort((a, b) => {
			const configuredDiff = Number(this.isProviderConfigured(b)) - Number(this.isProviderConfigured(a));
			if (configuredDiff !== 0) return configuredDiff;
			const aIsCurrent = modelsAreEqual(this.currentModel, a.model);
			const bIsCurrent = modelsAreEqual(this.currentModel, b.model);
			if (aIsCurrent !== bIsCurrent) return aIsCurrent ? -1 : 1;
			const rankDiff = this.recentRankOf(a) - this.recentRankOf(b);
			if (rankDiff !== 0) return rankDiff;
			const providerDiff = a.provider.localeCompare(b.provider);
			if (providerDiff !== 0) return providerDiff;
			const aFeatured = a.model.featured === true;
			const bFeatured = b.model.featured === true;
			if (aFeatured !== bFeatured) return aFeatured ? -1 : 1;
			return a.id.localeCompare(b.id, undefined, { numeric: true });
		});
		return sorted;
	}

	private getScopeText(): string {
		const allText = this.scope === "all" ? theme.fg("accent", "all") : theme.fg("muted", "all");
		const scopedText = this.scope === "scoped" ? theme.fg("accent", "scoped") : theme.fg("muted", "scoped");
		return `${theme.fg("muted", "Scope: ")}${allText}${theme.fg("muted", " | ")}${scopedText}`;
	}

	private getScopeHintText(): string {
		return keyHint("app.model.toggleScope", "scope") + theme.fg("muted", " (all/scoped)");
	}

	private setScope(scope: ModelScope): void {
		if (this.scope === scope) return;
		this.scope = scope;
		this.activeModels = this.scope === "scoped" ? this.scopedModelItems : this.allModels;
		this.provider = undefined;
		this.refreshProviders();
		const currentIndex = this.activeModels.findIndex((item) => modelsAreEqual(this.currentModel, item.model));
		this.selectedIndex = currentIndex >= 0 ? currentIndex : 0;
		this.filterModels(this.searchInput.getValue());
		if (this.scopeText) {
			this.scopeText.setText(this.getScopeText());
		}
	}

	private filterModels(query: string): void {
		const queryChanged = query !== this.searchQuery;
		this.searchQuery = query;
		const candidates = this.provider ? (this.providerModels.get(this.provider) ?? []) : this.activeModels;
		if (query.trim()) {
			const scored = fuzzyFilterScored(
				candidates,
				query,
				({ id, provider, model }) => `${id} ${provider} ${provider}/${id} ${provider} ${id} ${model.name}`,
			);
			scored.sort(
				(a, b) =>
					a.score - b.score ||
					Number(this.isProviderConfigured(b.item)) - Number(this.isProviderConfigured(a.item)) ||
					this.recentRankOf(a.item) - this.recentRankOf(b.item),
			);
			this.filteredModels = scored.map((r) => r.item);
		} else {
			this.filteredModels = candidates;
		}
		this.selectedIndex = queryChanged ? 0 : Math.min(this.selectedIndex, Math.max(0, this.getSelectableCount() - 1));
		this.updateList();
	}

	override render(width: number): string[] {
		const previousLayoutKey = this.responsiveLayoutKey;
		this.updateResponsiveLayout();
		if (this.responsiveLayoutKey !== previousLayoutKey) {
			this.updateList();
		}
		return super.render(width);
	}

	private updateList(): void {
		this.updateResponsiveLayout();
		this.listContainer.clear();

		if (this.warningText)
			this.warningText.setText(
				this.provider
					? keyHint("tui.select.cancel", "providers")
					: theme.fg("muted", "Signed-in providers first. Other models prompt sign-in."),
			);
		this.panel.setTitle(
			this.provider
				? `Zero · ${BUILT_IN_PROVIDER_DISPLAY_NAMES[this.provider] ?? this.provider}`
				: this.isProviderView()
					? "Zero · Select provider"
					: "Zero · Select model",
		);
		const maxVisible = this.listLayout.visibleItems;
		if (this.isProviderView()) {
			const start = Math.max(
				0,
				Math.min(this.selectedIndex - Math.floor(maxVisible / 2), this.providerItems.length - maxVisible),
			);
			const end = Math.min(start + maxVisible, this.providerItems.length);
			for (let i = start; i < end; i++) {
				// Provider metadata is precomputed; navigation only touches visible rows.
				const group = this.providerItems[i];
				const provider = group[0].provider;
				const info = this.providerInfo.get(provider)!;
				this.listContainer.addChild(
					new MenuRow({
						primary: BUILT_IN_PROVIDER_DISPLAY_NAMES[provider] ?? provider,
						secondary: `${group.length} model${group.length === 1 ? "" : "s"} · ${info.configured ? "signed in" : "sign in required"}`,
						meta: info.current ? "current" : "›",
						selected: i === this.selectedIndex,
					}),
				);
			}
			if (start > 0 || end < this.providerItems.length)
				this.listContainer.addChild(
					new Text(theme.fg("muted", `  (${this.selectedIndex + 1}/${this.providerItems.length})`), 0, 0),
				);
			return;
		}
		const selectedModelIndex = Math.min(this.selectedIndex, Math.max(0, this.filteredModels.length - 1));
		const startIndex = Math.max(
			0,
			Math.min(selectedModelIndex - Math.floor(maxVisible / 2), this.filteredModels.length - maxVisible),
		);
		const endIndex = Math.min(startIndex + maxVisible, this.filteredModels.length);

		let previousCategory: string | undefined;
		// Section headers are presentation only; navigation indexes model identities.
		for (let i = startIndex; i < endIndex; i++) {
			const item = this.filteredModels[i];
			if (!item) continue;

			const isSelected = i === this.selectedIndex;
			const isCurrent = modelsAreEqual(this.currentModel, item.model);
			const isConfigured = this.isProviderConfigured(item);
			if (this.shouldShowSections()) {
				const category = isCurrent
					? "Current"
					: this.recentRank.has(this.getModelKey(item))
						? "Recent"
						: item.provider;
				if (category !== previousCategory) {
					this.listContainer.addChild(new TruncatedText(theme.bold(theme.fg("accent", category)), 0, 0));
					previousCategory = category;
				}
			}
			const meta = isConfigured
				? isCurrent
					? theme.fg("success", "current")
					: undefined
				: theme.fg("warning", isCurrent ? "current · sign in" : "sign in");

			this.listContainer.addChild(
				new MenuRow({
					primary: item.model.name && item.model.name !== item.id ? `${item.model.name} (${item.id})` : item.id,
					secondary: this.provider
						? `${item.model.contextWindow.toLocaleString()} token context${item.model.reasoning ? " · reasoning" : ""}${item.model.input.includes("image") ? " · vision" : ""}`
						: item.provider,
					meta,
					selected: isSelected,
				}),
			);
		}

		// Add scroll indicator if needed
		if (startIndex > 0 || endIndex < this.filteredModels.length) {
			const scrollInfo = theme.fg("muted", `  (${selectedModelIndex + 1}/${this.filteredModels.length})`);
			this.listContainer.addChild(new Text(scrollInfo, 0, 0));
		}

		// Show error message or "no results" if empty
		if (this.errorMessage) {
			// Show error in red
			const errorLines = this.errorMessage.split("\n");
			for (const line of errorLines) {
				this.listContainer.addChild(new Text(theme.fg("error", line), 0, 0));
			}
		} else if (this.filteredModels.length === 0) {
			this.listContainer.addChild(new Text(theme.fg("muted", "No matching models"), 0, 0));
		} else {
			const selected = this.filteredModels[this.selectedIndex];
			if (selected && this.shouldShowSelectedDetails()) {
				this.listContainer.addChild(new Spacer(1));
				this.listContainer.addChild(new Text(theme.fg("muted", selected.model.name), 0, 0));
			}
		}
	}

	handleInput(keyData: string): void {
		const kb = getKeybindings();
		if (kb.matches(keyData, "app.model.toggleScope")) {
			if (this.scopedModelItems.length > 0) {
				const nextScope: ModelScope = this.scope === "all" ? "scoped" : "all";
				this.setScope(nextScope);
				if (this.scopeHintText) {
					this.scopeHintText.setText(this.getScopeHintText());
				}
			}
			return;
		}
		// Up arrow - wrap to bottom when at top
		if (kb.matches(keyData, "tui.select.up")) {
			const selectableCount = this.getSelectableCount();
			if (selectableCount === 0) return;
			this.selectedIndex = this.selectedIndex === 0 ? selectableCount - 1 : this.selectedIndex - 1;
			this.updateList();
		}
		// Down arrow - wrap to top when at bottom
		else if (kb.matches(keyData, "tui.select.down")) {
			const selectableCount = this.getSelectableCount();
			if (selectableCount === 0) return;
			this.selectedIndex = this.selectedIndex === selectableCount - 1 ? 0 : this.selectedIndex + 1;
			this.updateList();
		}
		// Enter
		else if (kb.matches(keyData, "tui.select.confirm")) {
			this.handleConfirm();
		}
		// Escape / Ctrl+C, or left arrow when the search field is at its start
		else if (kb.matches(keyData, "tui.select.cancel") || shouldTreatAsBack(keyData, this.searchInput)) {
			if (this.provider) {
				const previousProvider = this.provider;
				this.provider = undefined;
				this.searchInput.setValue("");
				this.filterModels("");
				this.selectedIndex = Math.max(
					0,
					this.providerItems.findIndex((group) => group[0].provider === previousProvider),
				);
				this.updateList();
			} else {
				this.onCancelCallback();
			}
		}
		// Pass everything else to search input
		else {
			this.searchInput.handleInput(keyData);
			this.filterModels(this.searchInput.getValue());
		}
	}

	private handleSelect(model: Model<any>): void {
		this.onSelectCallback(model);
	}

	private handleConfirm(): void {
		if (this.isProviderView()) {
			const group = this.providerItems[this.selectedIndex];
			if (!group) return;
			this.provider = group[0].provider;
			this.filterModels("");
			const current = this.filteredModels.findIndex((item) => modelsAreEqual(this.currentModel, item.model));
			this.selectedIndex = Math.max(0, current);
			this.updateList();
			return;
		}
		const selectedModel = this.filteredModels[this.selectedIndex];
		if (selectedModel) {
			this.handleSelect(selectedModel.model);
			return;
		}
	}

	private getSelectableCount(): number {
		return this.isProviderView() ? this.providerItems.length : this.filteredModels.length;
	}

	getSearchInput(): MenuSearchInput {
		return this.searchInput;
	}

	private updateResponsiveLayout(): void {
		const showHeaderHelp = this.shouldShowHeaderHelp();
		let headerHelpRows = 0;
		this.headerHelpContainer.clear();
		if (showHeaderHelp) {
			if (this.scopeText && this.scopeHintText) {
				this.headerHelpContainer.addChild(this.scopeText);
				this.headerHelpContainer.addChild(this.scopeHintText);
				headerHelpRows += 2;
			} else if (this.warningText) {
				this.headerHelpContainer.addChild(this.warningText);
				headerHelpRows += 1;
			}
			this.headerHelpContainer.addChild(new Spacer(1));
			headerHelpRows += 1;
		}

		const headerRows = this.getHeaderRows();
		const reservedRows =
			MODEL_LIST_RESERVED_ROWS.base +
			headerRows +
			headerHelpRows +
			(this.shouldShowSelectedDetails() ? MODEL_LIST_RESERVED_ROWS.detail : 0);
		this.listLayout = getMenuListLayout({
			getRows: this.viewport.getRows,
			preferredVisibleItems: PREFERRED_VISIBLE_MODELS,
			totalItems: this.getSelectableCount(),
			reservedRows,
			comfortableItemRows: this.shouldShowSections() ? 3 : 2,
			compactItemRows: this.shouldShowSections() ? 3 : 2,
			comfortableListPaddingRows: 0,
			scrollIndicatorRows: MODEL_SCROLL_INDICATOR_ROWS,
		});
		this.responsiveLayoutKey = [
			headerRows,
			showHeaderHelp ? "help" : "no-help",
			headerHelpRows,
			this.shouldShowSelectedDetails() ? "detail" : "no-detail",
			this.shouldShowSections() ? "sections" : "flat",
			this.listLayout.compact ? "compact" : "comfortable",
			this.listLayout.visibleItems,
		].join(":");
	}

	private shouldShowHeaderHelp(): boolean {
		return this.hasRows(MODEL_HELP_MIN_ROWS);
	}

	private shouldShowSections(): boolean {
		return !this.provider && !this.isProviderView() && !this.searchQuery.trim() && this.hasRows(16);
	}

	private shouldShowSelectedDetails(): boolean {
		return !this.provider && !this.isProviderView() && this.hasRows(MODEL_DETAIL_MIN_ROWS);
	}

	private hasRows(minRows: number): boolean {
		const rows = this.viewport.getRows?.();
		return rows === undefined || !Number.isFinite(rows) || rows >= minRows;
	}
}
