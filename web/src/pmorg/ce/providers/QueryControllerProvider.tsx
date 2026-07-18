"use client";

import type { ReactNode } from "react";

interface QueryControllerProviderProps {
  children: ReactNode;
}

/**
 * Community builds keep the provider boundary but never install the paid
 * query-classification and document-search implementation.
 */
export function QueryControllerProvider({
  children,
}: QueryControllerProviderProps) {
  return <>{children}</>;
}
