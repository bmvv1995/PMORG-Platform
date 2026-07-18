import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const WEB_ROOT = path.resolve(__dirname, "../../..");
const SRC_ROOT = path.join(WEB_ROOT, "src");
const EXCLUDED_ROOTS = [
  path.join(SRC_ROOT, "app", "ee"),
  path.join(SRC_ROOT, "ee"),
];
const SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx"]);

function isInside(candidate: string, root: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === "" ||
    (!relative.startsWith("..") && !path.isAbsolute(relative))
  );
}

function sourceFiles(root: string): string[] {
  return fs.readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const candidate = path.join(root, entry.name);
    if (
      EXCLUDED_ROOTS.some((excludedRoot) => isInside(candidate, excludedRoot))
    ) {
      return [];
    }
    if (entry.isDirectory()) return sourceFiles(candidate);
    return SOURCE_EXTENSIONS.has(path.extname(entry.name)) ? [candidate] : [];
  });
}

function moduleSpecifiers(filePath: string): string[] {
  const sourceText = fs.readFileSync(filePath, "utf8");
  const scriptKind = filePath.endsWith("x")
    ? ts.ScriptKind.TSX
    : filePath.endsWith(".js") || filePath.endsWith(".jsx")
      ? ts.ScriptKind.JS
      : ts.ScriptKind.TS;
  const sourceFile = ts.createSourceFile(
    filePath,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    scriptKind
  );
  const specifiers: string[] = [];

  function visit(node: ts.Node) {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      specifiers.push(node.moduleSpecifier.text);
    }

    if (ts.isCallExpression(node)) {
      const [argument] = node.arguments;
      if (
        argument &&
        ts.isStringLiteral(argument) &&
        (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
          (ts.isIdentifier(node.expression) &&
            node.expression.text === "require"))
      ) {
        specifiers.push(argument.text);
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return specifiers;
}

function resolveLocalImport(
  importer: string,
  specifier: string
): string | null {
  if (specifier.startsWith("@/")) {
    return path.resolve(SRC_ROOT, specifier.slice(2));
  }
  if (specifier.startsWith("./") || specifier.startsWith("../")) {
    return path.resolve(path.dirname(importer), specifier);
  }
  return null;
}

describe("PMORG CE source boundary", () => {
  it("has no retained import edge into excluded Enterprise trees", () => {
    const violations = sourceFiles(SRC_ROOT).flatMap((filePath) =>
      moduleSpecifiers(filePath).flatMap((specifier) => {
        const resolved = resolveLocalImport(filePath, specifier);
        if (
          !resolved ||
          !EXCLUDED_ROOTS.some((root) => isInside(resolved, root))
        ) {
          return [];
        }
        return [`${path.relative(WEB_ROOT, filePath)} -> ${specifier}`];
      })
    );

    expect(violations).toEqual([]);
  });
});
