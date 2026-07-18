"use client";

import type { MinimalOnyxDocument } from "@/lib/search/interfaces";

interface SearchResultsProps {
  onDocumentClick: (document: MinimalOnyxDocument) => void;
}

/**
 * Paid search has no renderable surface in the PMORG Community artifact.
 * The surrounding query controller is also a pass-through, so this component
 * is a final fail-closed boundary rather than a user-visible empty state.
 */
export default function SearchUI(_props: SearchResultsProps) {
  return null;
}
