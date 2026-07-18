import type { BaseFilters, SearchFullResponse } from "@/lib/search/interfaces";

export const knowledgeDocumentSearchAvailable = false;

interface SearchDocumentsOptions {
  filters?: BaseFilters;
  numHits?: number;
  includeContent?: boolean;
  signal?: AbortSignal;
}

export class UnsupportedPMORGCEFeatureError extends Error {
  constructor(feature: string) {
    super(`${feature} is not available in the PMORG Community artifact`);
    this.name = "UnsupportedPMORGCEFeatureError";
    Object.setPrototypeOf(this, UnsupportedPMORGCEFeatureError.prototype);
  }
}

export function searchDocuments(
  _query: string,
  _options?: SearchDocumentsOptions
): Promise<SearchFullResponse> {
  return Promise.reject(
    new UnsupportedPMORGCEFeatureError("Document search UI")
  );
}
