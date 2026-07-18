"use client";

import type { StandardAnswerCategory } from "@/lib/types";

interface UnavailableStandardAnswerCategories {
  data: StandardAnswerCategory[] | undefined;
  isLoading: false;
  error: undefined;
  refreshStandardAnswerCategories: () => Promise<undefined>;
}

/**
 * Standard-answer categories are Enterprise-only. Keep the hook-shaped seam
 * so the shared Slack form receives the explicit Community response.
 */
export function useStandardAnswerCategories(): UnavailableStandardAnswerCategories {
  return {
    data: undefined,
    isLoading: false,
    error: undefined,
    refreshStandardAnswerCategories: () => Promise.resolve(undefined),
  };
}
