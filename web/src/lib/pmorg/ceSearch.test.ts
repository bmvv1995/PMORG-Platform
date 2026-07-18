import {
  knowledgeDocumentSearchAvailable,
  searchDocuments,
  UnsupportedPMORGCEFeatureError,
} from "@/lib/pmorg/ceSearch";

describe("PMORG CE document search boundary", () => {
  it("declares the paid document-search surface unavailable", () => {
    expect(knowledgeDocumentSearchAvailable).toBe(false);
  });

  it("fails closed if the unavailable adapter is called", async () => {
    await expect(searchDocuments("status")).rejects.toBeInstanceOf(
      UnsupportedPMORGCEFeatureError
    );
  });
});
