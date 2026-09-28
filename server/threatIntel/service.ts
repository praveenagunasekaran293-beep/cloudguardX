import { ThreatIntelProvider } from "./provider.js";
import { SyntheticDemoThreatIntelProvider, detectIndicatorType } from "./syntheticProvider.js";
import { EnrichedIndicator, IndicatorType, ThreatIntelFilter } from "./types.js";

/**
 * ThreatIntelService
 * Modular threat intelligence abstraction layer for CyberSentinel X.
 * Decouples consumer routes and UI from the concrete data provider.
 */
export class ThreatIntelService {
  private static instance: ThreatIntelService;
  private providers: Map<string, ThreatIntelProvider> = new Map();
  private activeProviderId: string;

  private constructor() {
    // Register default synthetic demo provider
    const synthetic = new SyntheticDemoThreatIntelProvider();
    this.providers.set(synthetic.id, synthetic);
    this.activeProviderId = synthetic.id;
  }

  public static getInstance(): ThreatIntelService {
    if (!ThreatIntelService.instance) {
      ThreatIntelService.instance = new ThreatIntelService();
    }
    return ThreatIntelService.instance;
  }

  /**
   * Register a new threat intelligence provider (e.g. real external provider in future)
   */
  public registerProvider(provider: ThreatIntelProvider): void {
    this.providers.set(provider.id, provider);
  }

  /**
   * Switch the active threat intelligence provider
   */
  public setActiveProvider(providerId: string): boolean {
    if (this.providers.has(providerId)) {
      this.activeProviderId = providerId;
      return true;
    }
    return false;
  }

  /**
   * Get the active provider instance
   */
  public getActiveProvider(): ThreatIntelProvider {
    const provider = this.providers.get(this.activeProviderId);
    if (!provider) {
      const fallback = new SyntheticDemoThreatIntelProvider();
      this.providers.set(fallback.id, fallback);
      return fallback;
    }
    return provider;
  }

  /**
   * List all registered providers and their status
   */
  public getRegisteredProviders(): Array<{
    id: string;
    name: string;
    isSynthetic: boolean;
    isActive: boolean;
    description: string;
  }> {
    return Array.from(this.providers.values()).map((p) => ({
      id: p.id,
      name: p.name,
      isSynthetic: p.isSynthetic,
      isActive: p.id === this.activeProviderId,
      description: p.description,
    }));
  }

  /**
   * Look up an indicator with automatic type detection and enrichment
   */
  public async lookup(indicator: string, typeHint?: IndicatorType): Promise<EnrichedIndicator | null> {
    const provider = this.getActiveProvider();
    return provider.lookup(indicator, typeHint);
  }

  /**
   * List indicators matching filter
   */
  public async listIndicators(filter?: ThreatIntelFilter): Promise<{
    indicators: EnrichedIndicator[];
    total: number;
    activeProvider: string;
    isSynthetic: boolean;
  }> {
    const provider = this.getActiveProvider();
    const list = await provider.list(filter);
    return {
      indicators: list,
      total: list.length,
      activeProvider: provider.name,
      isSynthetic: provider.isSynthetic,
    };
  }

  /**
   * Batch enrich indicators for an incident or event
   */
  public async enrichIndicators(indicators: string[]): Promise<EnrichedIndicator[]> {
    const provider = this.getActiveProvider();
    return provider.enrich(indicators);
  }

  /**
   * Autodetect indicator type
   */
  public detectType(indicator: string): IndicatorType {
    return detectIndicatorType(indicator);
  }
}

export const threatIntelService = ThreatIntelService.getInstance();
