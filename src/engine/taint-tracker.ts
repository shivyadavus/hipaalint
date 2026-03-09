import { dirname, resolve } from 'path';
import ts from 'typescript';
import type { ComplianceFinding, Rule } from './types.js';

const SOURCE_TOKEN = 'source';
const FILE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mts', '.cts', '.mjs', '.cjs'];
const LOG_OBJECTS = new Set(['console', 'logger', 'logging']);
const LOG_METHODS = new Set(['log', 'error', 'warn', 'info', 'debug', 'warning', 'print']);
const RESPONSE_OBJECTS = new Set(['res', 'response', 'ctx']);
const RESPONSE_METHODS = new Set(['json', 'send', 'write', 'end']);
const FILE_NAME_CANDIDATES = ['', '.ts', '.tsx', '.js', '.jsx', '.mts', '.cts', '.mjs', '.cjs'];
const INDEX_NAME_CANDIDATES = [
  '/index.ts',
  '/index.tsx',
  '/index.js',
  '/index.jsx',
  '/index.mts',
  '/index.cts',
  '/index.mjs',
  '/index.cjs',
];

const TAINT_SOURCES = new Set([
  'ssn',
  'socialsecuritynumber',
  'social_security_number',
  'patientname',
  'patient_name',
  'patientfirstname',
  'patientlastname',
  'firstname',
  'lastname',
  'dateofbirth',
  'date_of_birth',
  'dob',
  'patientdob',
  'mrn',
  'medicalrecordnumber',
  'medical_record_number',
  'diagnosis',
  'medication',
  'prescription',
  'treatment',
  'healthplanid',
  'health_plan_id',
  'patientemail',
  'patient_email',
  'patientphone',
  'patient_phone',
  'patientaddress',
  'patient_address',
  'insuranceid',
  'insurance_id',
  'record',
  'patient',
]);

type DependencyToken = typeof SOURCE_TOKEN | `param:${number}`;
type SinkKind = 'log' | 'response' | 'error';

interface TaintFile {
  filePath: string;
  content: string;
}

interface ImportBinding {
  sourcePath: string;
  exportName: string;
}

interface NamespaceImportBinding {
  sourcePath: string;
}

interface FunctionInfo {
  name: string;
  node: ts.FunctionLikeDeclaration;
  filePath: string;
  sourceFile: ts.SourceFile;
  params: string[];
}

interface ModuleInfo {
  filePath: string;
  content: string;
  sourceFile: ts.SourceFile;
  imports: Map<string, ImportBinding>;
  namespaceImports: Map<string, NamespaceImportBinding>;
  functions: Map<string, FunctionInfo>;
  exportedValues: Map<string, string>;
  exportedFunctions: Map<string, string>;
}

interface SinkEvent {
  kind: SinkKind;
  calleeText: string;
  filePath: string;
  lineNumber: number;
  columnNumber: number;
  codeSnippet: string;
  dependencies: DependencyToken[];
}

interface FunctionSummary {
  returnDependencies: DependencyToken[];
  sinkEvents: SinkEvent[];
}

interface ProjectAnalysisContext {
  modules: Map<string, ModuleInfo>;
  functionSummaries: Map<string, FunctionSummary>;
  exportedValueDeps: Map<string, Map<string, DependencyToken[]>>;
}

interface RuleMatcher {
  kind: SinkKind;
  functionNames?: Set<string>;
}

function isSupportedFile(filePath: string): boolean {
  return FILE_EXTENSIONS.some((ext) => filePath.endsWith(ext));
}

function normalizePath(path: string): string {
  return path.replace(/\\/g, '/');
}

function getNodeLocation(
  sourceFile: ts.SourceFile,
  node: ts.Node,
): { lineNumber: number; columnNumber: number } {
  const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return { lineNumber: position.line + 1, columnNumber: position.character + 1 };
}

function sanitizeSnippet(text: string): string {
  let snippet = text.trim().replace(/\s+/g, ' ');
  snippet = snippet.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED-SSN]');
  snippet = snippet.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED-EMAIL]');
  if (snippet.length > 200) {
    return `${snippet.slice(0, 200)}...`;
  }
  return snippet;
}

function isTaintSourceName(name: string): boolean {
  return TAINT_SOURCES.has(name.toLowerCase());
}

function sortDependencies(deps: Iterable<DependencyToken>): DependencyToken[] {
  return [...new Set(deps)].sort();
}

function mergeDependencies(...sets: Array<Iterable<DependencyToken>>): DependencyToken[] {
  const merged = new Set<DependencyToken>();
  for (const set of sets) {
    for (const dep of set) {
      merged.add(dep);
    }
  }
  return sortDependencies(merged);
}

function hasDependencies(deps: Iterable<DependencyToken>): boolean {
  for (const _ of deps) {
    return true;
  }
  return false;
}

function mapDependencies(
  deps: Iterable<DependencyToken>,
  argDeps: DependencyToken[][],
): DependencyToken[] {
  const mapped = new Set<DependencyToken>();
  for (const dep of deps) {
    if (dep === SOURCE_TOKEN) {
      mapped.add(SOURCE_TOKEN);
      continue;
    }
    const index = Number(dep.slice('param:'.length));
    for (const argDep of argDeps[index] ?? []) {
      mapped.add(argDep);
    }
  }
  return sortDependencies(mapped);
}

function serializeSummary(summary: FunctionSummary): string {
  return JSON.stringify({
    returnDependencies: summary.returnDependencies,
    sinkEvents: summary.sinkEvents.map((event) => ({
      kind: event.kind,
      calleeText: event.calleeText,
      filePath: event.filePath,
      lineNumber: event.lineNumber,
      columnNumber: event.columnNumber,
      codeSnippet: event.codeSnippet,
      dependencies: event.dependencies,
    })),
  });
}

function resolveModulePath(
  fromFilePath: string,
  specifier: string,
  modules: Map<string, ModuleInfo>,
): string | null {
  if (!specifier.startsWith('.')) return null;

  const raw = normalizePath(resolve(dirname(fromFilePath), specifier));

  const candidates = new Set<string>();
  for (const candidate of FILE_NAME_CANDIDATES) {
    candidates.add(`${raw}${candidate}`);
  }
  for (const candidate of INDEX_NAME_CANDIDATES) {
    candidates.add(`${raw}${candidate}`);
  }

  for (const candidate of candidates) {
    if (modules.has(candidate)) return candidate;
  }

  return null;
}

function buildModules(files: TaintFile[]): Map<string, ModuleInfo> {
  const modules = new Map<string, ModuleInfo>();

  for (const file of files) {
    if (!isSupportedFile(file.filePath)) continue;

    const filePath = normalizePath(file.filePath);
    const sourceFile = ts.createSourceFile(filePath, file.content, ts.ScriptTarget.Latest, true);
    const moduleInfo: ModuleInfo = {
      filePath,
      content: file.content,
      sourceFile,
      imports: new Map(),
      namespaceImports: new Map(),
      functions: new Map(),
      exportedValues: new Map(),
      exportedFunctions: new Map(),
    };

    modules.set(filePath, moduleInfo);
  }

  for (const module of modules.values()) {
    collectModuleBindings(module, modules);
  }

  return modules;
}

function collectModuleBindings(module: ModuleInfo, modules: Map<string, ModuleInfo>): void {
  const recordExportedBinding = (localName: string, exportName: string): void => {
    if (module.functions.has(localName)) {
      module.exportedFunctions.set(exportName, localName);
    } else {
      module.exportedValues.set(exportName, localName);
    }
  };

  const visitTopLevel = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const resolved = resolveModulePath(module.filePath, node.moduleSpecifier.text, modules);
      if (!resolved || !node.importClause) return;

      if (node.importClause.name) {
        module.imports.set(node.importClause.name.text, {
          sourcePath: resolved,
          exportName: 'default',
        });
      }

      const bindings = node.importClause.namedBindings;
      if (bindings && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) {
          module.imports.set(element.name.text, {
            sourcePath: resolved,
            exportName: element.propertyName?.text ?? element.name.text,
          });
        }
      } else if (bindings && ts.isNamespaceImport(bindings)) {
        module.namespaceImports.set(bindings.name.text, { sourcePath: resolved });
      }
      return;
    }

    if (ts.isFunctionDeclaration(node) && node.name) {
      module.functions.set(node.name.text, {
        name: node.name.text,
        node,
        filePath: module.filePath,
        sourceFile: module.sourceFile,
        params: extractFunctionParamNames(node),
      });
      if (hasExportModifier(node)) {
        module.exportedFunctions.set(node.name.text, node.name.text);
      }
      if (hasDefaultModifier(node)) {
        module.exportedFunctions.set('default', node.name.text);
      }
      return;
    }

    if (ts.isVariableStatement(node)) {
      const exported = hasExportModifier(node);
      const isDefault = hasDefaultModifier(node);
      for (const declaration of node.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        const localName = declaration.name.text;
        const initializer = declaration.initializer;
        if (
          initializer &&
          (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer))
        ) {
          module.functions.set(localName, {
            name: localName,
            node: initializer,
            filePath: module.filePath,
            sourceFile: module.sourceFile,
            params: extractFunctionParamNames(initializer),
          });
          if (exported) {
            module.exportedFunctions.set(localName, localName);
          }
          if (isDefault) {
            module.exportedFunctions.set('default', localName);
          }
        } else if (exported) {
          module.exportedValues.set(localName, localName);
          if (isDefault) {
            module.exportedValues.set('default', localName);
          }
        }
      }
      return;
    }

    if (ts.isExportAssignment(node)) {
      if (ts.isIdentifier(node.expression)) {
        recordExportedBinding(node.expression.text, 'default');
      }
      return;
    }

    if (ts.isExportDeclaration(node) && node.exportClause && ts.isNamedExports(node.exportClause)) {
      for (const element of node.exportClause.elements) {
        const localName = element.propertyName?.text ?? element.name.text;
        const exportName = element.name.text;
        recordExportedBinding(localName, exportName);
      }
    }
  };

  for (const statement of module.sourceFile.statements) {
    visitTopLevel(statement);
  }
}

function hasExportModifier(node: ts.Node): boolean {
  return Boolean(ts.getCombinedModifierFlags(node as ts.Declaration) & ts.ModifierFlags.Export);
}

function hasDefaultModifier(node: ts.Node): boolean {
  return Boolean(ts.getCombinedModifierFlags(node as ts.Declaration) & ts.ModifierFlags.Default);
}

function extractFunctionParamNames(node: ts.FunctionLikeDeclaration): string[] {
  return node.parameters.map((parameter, index) => {
    if (ts.isIdentifier(parameter.name)) return parameter.name.text;
    return `param${index}`;
  });
}

function getImportedValueDependencies(
  module: ModuleInfo,
  identifier: string,
  context: ProjectAnalysisContext,
): DependencyToken[] {
  const binding = module.imports.get(identifier);
  if (!binding) return [];
  const exportedValues = context.exportedValueDeps.get(binding.sourcePath);
  if (!exportedValues) return [];
  return exportedValues.get(binding.exportName) ?? [];
}

function resolveFunctionSummary(
  module: ModuleInfo,
  expression: ts.LeftHandSideExpression,
  context: ProjectAnalysisContext,
): FunctionSummary | null {
  if (ts.isIdentifier(expression)) {
    const local = module.functions.get(expression.text);
    if (local) {
      return context.functionSummaries.get(`${module.filePath}::${local.name}`) ?? null;
    }

    const binding = module.imports.get(expression.text);
    if (binding) {
      const importedModule = context.modules.get(binding.sourcePath);
      const localName = importedModule?.exportedFunctions.get(binding.exportName);
      if (!localName || !importedModule) return null;
      return context.functionSummaries.get(`${importedModule.filePath}::${localName}`) ?? null;
    }
  }

  if (ts.isPropertyAccessExpression(expression) && ts.isIdentifier(expression.expression)) {
    const namespaceImport = module.namespaceImports.get(expression.expression.text);
    if (!namespaceImport) return null;
    const importedModule = context.modules.get(namespaceImport.sourcePath);
    const localName = importedModule?.exportedFunctions.get(expression.name.text);
    if (!localName || !importedModule) return null;
    return context.functionSummaries.get(`${importedModule.filePath}::${localName}`) ?? null;
  }

  return null;
}

function getCallText(expression: ts.LeftHandSideExpression): string {
  if (ts.isPropertyAccessExpression(expression)) {
    return `${getCallText(expression.expression as ts.LeftHandSideExpression)}.${expression.name.text}`;
  }
  if (ts.isIdentifier(expression)) {
    return expression.text;
  }
  return expression.getText();
}

function getDirectSink(call: ts.CallExpression): { kind: SinkKind; calleeText: string } | null {
  if (ts.isIdentifier(call.expression) && LOG_METHODS.has(call.expression.text)) {
    return { kind: 'log', calleeText: call.expression.text };
  }

  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const objectText = getCallText(call.expression.expression as ts.LeftHandSideExpression);
  const methodText = call.expression.name.text;
  const calleeText = `${objectText}.${methodText}`;

  if (LOG_OBJECTS.has(objectText) && LOG_METHODS.has(methodText)) {
    return { kind: 'log', calleeText };
  }

  if (RESPONSE_OBJECTS.has(objectText) && RESPONSE_METHODS.has(methodText)) {
    return { kind: 'response', calleeText };
  }

  return null;
}

function evaluateExpression(
  module: ModuleInfo,
  env: Map<string, DependencyToken[]>,
  expression: ts.Expression | undefined,
  context: ProjectAnalysisContext,
): DependencyToken[] {
  if (!expression) return [];

  if (ts.isIdentifier(expression)) {
    return mergeDependencies(
      env.get(expression.text) ?? [],
      getImportedValueDependencies(module, expression.text, context),
    );
  }

  if (ts.isPropertyAccessExpression(expression)) {
    const objectDeps = evaluateExpression(module, env, expression.expression, context);
    if (hasDependencies(objectDeps) || isTaintSourceName(expression.name.text)) {
      return mergeDependencies(
        objectDeps,
        isTaintSourceName(expression.name.text) ? [SOURCE_TOKEN] : [],
      );
    }
    return [];
  }

  if (ts.isElementAccessExpression(expression)) {
    return mergeDependencies(
      evaluateExpression(module, env, expression.expression, context),
      evaluateExpression(module, env, expression.argumentExpression, context),
    );
  }

  if (
    ts.isParenthesizedExpression(expression) ||
    ts.isNonNullExpression(expression) ||
    ts.isAsExpression(expression) ||
    ts.isTypeAssertionExpression(expression) ||
    ts.isSatisfiesExpression(expression)
  ) {
    return evaluateExpression(module, env, expression.expression, context);
  }

  if (ts.isAwaitExpression(expression)) {
    return evaluateExpression(module, env, expression.expression, context);
  }

  if (ts.isConditionalExpression(expression)) {
    return mergeDependencies(
      evaluateExpression(module, env, expression.condition, context),
      evaluateExpression(module, env, expression.whenTrue, context),
      evaluateExpression(module, env, expression.whenFalse, context),
    );
  }

  if (ts.isBinaryExpression(expression)) {
    return mergeDependencies(
      evaluateExpression(module, env, expression.left, context),
      evaluateExpression(module, env, expression.right, context),
    );
  }

  if (ts.isTemplateExpression(expression)) {
    return mergeDependencies(
      ...expression.templateSpans.map((span) =>
        evaluateExpression(module, env, span.expression, context),
      ),
    );
  }

  if (ts.isTaggedTemplateExpression(expression)) {
    return mergeDependencies(
      evaluateExpression(module, env, expression.tag, context),
      evaluateExpression(module, env, expression.template, context),
    );
  }

  if (ts.isTemplateLiteral(expression)) {
    return [];
  }

  if (ts.isArrayLiteralExpression(expression)) {
    return mergeDependencies(
      ...expression.elements.map((element) =>
        ts.isSpreadElement(element)
          ? evaluateExpression(module, env, element.expression, context)
          : ts.isExpression(element)
            ? evaluateExpression(module, env, element, context)
            : [],
      ),
    );
  }

  if (ts.isObjectLiteralExpression(expression)) {
    return mergeDependencies(
      ...expression.properties.map((property) => {
        if (ts.isSpreadAssignment(property)) {
          return evaluateExpression(module, env, property.expression, context);
        }
        if (ts.isShorthandPropertyAssignment(property)) {
          return evaluateExpression(module, env, property.name, context);
        }
        if (ts.isPropertyAssignment(property)) {
          const name = ts.isIdentifier(property.name)
            ? property.name.text
            : property.name.getText();
          const propertyDeps = evaluateExpression(module, env, property.initializer, context);
          if (isTaintSourceName(name)) {
            return mergeDependencies(propertyDeps, [SOURCE_TOKEN]);
          }
          return propertyDeps;
        }
        if (ts.isMethodDeclaration(property) && property.body) {
          return [];
        }
        return [];
      }),
    );
  }

  if (ts.isCallExpression(expression)) {
    const summary = resolveFunctionSummary(module, expression.expression, context);
    if (!summary) {
      return [];
    }
    const argDeps = expression.arguments.map((argument) =>
      evaluateExpression(module, env, argument, context),
    );
    return mapDependencies(summary.returnDependencies, argDeps);
  }

  if (ts.isNewExpression(expression)) {
    return mergeDependencies(
      evaluateExpression(module, env, expression.expression as ts.Expression, context),
      ...(expression.arguments ?? []).map((argument) =>
        evaluateExpression(module, env, argument, context),
      ),
    );
  }

  if (ts.isPrefixUnaryExpression(expression) || ts.isPostfixUnaryExpression(expression)) {
    return evaluateExpression(module, env, expression.operand, context);
  }

  if (
    ts.isPropertyAccessChain?.(expression) ||
    ts.isElementAccessChain?.(expression) ||
    ts.isCallChain?.(expression)
  ) {
    return evaluateExpression(module, env, expression.expression as ts.Expression, context);
  }

  return [];
}

function assignBindingName(
  module: ModuleInfo,
  env: Map<string, DependencyToken[]>,
  name: ts.BindingName,
  baseDeps: DependencyToken[],
  context: ProjectAnalysisContext,
): void {
  if (ts.isIdentifier(name)) {
    const deps = isTaintSourceName(name.text)
      ? mergeDependencies(baseDeps, [SOURCE_TOKEN])
      : baseDeps;
    env.set(name.text, deps);
    return;
  }

  if (ts.isObjectBindingPattern(name)) {
    for (const element of name.elements) {
      const propertyName =
        element.propertyName && ts.isIdentifier(element.propertyName)
          ? element.propertyName.text
          : element.name.getText();
      const initializerDeps = element.initializer
        ? evaluateExpression(module, env, element.initializer, context)
        : [];
      const deps = isTaintSourceName(propertyName)
        ? mergeDependencies(baseDeps, initializerDeps, [SOURCE_TOKEN])
        : mergeDependencies(baseDeps, initializerDeps);
      assignBindingName(module, env, element.name, deps, context);
    }
    return;
  }

  for (const element of name.elements) {
    if (!ts.isBindingElement(element)) continue;
    const initializerDeps = element.initializer
      ? evaluateExpression(module, env, element.initializer, context)
      : [];
    assignBindingName(
      module,
      env,
      element.name,
      mergeDependencies(baseDeps, initializerDeps),
      context,
    );
  }
}

function createSinkEvent(
  kind: SinkKind,
  calleeText: string,
  module: ModuleInfo,
  node: ts.Node,
  dependencies: DependencyToken[],
): SinkEvent {
  const location = getNodeLocation(module.sourceFile, node);
  return {
    kind,
    calleeText,
    filePath: module.filePath,
    lineNumber: location.lineNumber,
    columnNumber: location.columnNumber,
    codeSnippet: sanitizeSnippet(node.getText(module.sourceFile)),
    dependencies: sortDependencies(dependencies),
  };
}

function analyzeStatementList(
  module: ModuleInfo,
  statements: readonly ts.Statement[],
  initialEnv: Map<string, DependencyToken[]>,
  context: ProjectAnalysisContext,
): { env: Map<string, DependencyToken[]>; sinkEvents: SinkEvent[]; returnDeps: DependencyToken[] } {
  const env = new Map(initialEnv);
  const sinkEvents: SinkEvent[] = [];
  let returnDeps: DependencyToken[] = [];

  const visitNode = (node: ts.Node): void => {
    if (ts.isVariableStatement(node)) {
      for (const declaration of node.declarationList.declarations) {
        const initializerDeps = evaluateExpression(module, env, declaration.initializer, context);
        assignBindingName(module, env, declaration.name, initializerDeps, context);
      }
      return;
    }

    if (ts.isExpressionStatement(node)) {
      visitExpression(node.expression);
      return;
    }

    if (ts.isReturnStatement(node)) {
      returnDeps = mergeDependencies(
        returnDeps,
        evaluateExpression(module, env, node.expression, context),
      );
      return;
    }

    if (ts.isThrowStatement(node)) {
      const deps = evaluateExpression(module, env, node.expression, context);
      if (hasDependencies(deps)) {
        sinkEvents.push(createSinkEvent('error', 'throw', module, node, deps));
      }
      return;
    }

    if (ts.isIfStatement(node)) {
      const conditionDeps = evaluateExpression(module, env, node.expression, context);
      const whenTrue = analyzeStatementList(
        module,
        ts.isBlock(node.thenStatement) ? node.thenStatement.statements : [node.thenStatement],
        env,
        context,
      );
      const whenFalse = node.elseStatement
        ? analyzeStatementList(
            module,
            ts.isBlock(node.elseStatement) ? node.elseStatement.statements : [node.elseStatement],
            env,
            context,
          )
        : {
            env: new Map<string, DependencyToken[]>(),
            sinkEvents: [],
            returnDeps: [] as DependencyToken[],
          };

      sinkEvents.push(...whenTrue.sinkEvents, ...whenFalse.sinkEvents);
      returnDeps = mergeDependencies(
        returnDeps,
        conditionDeps,
        whenTrue.returnDeps,
        whenFalse.returnDeps,
      );
      for (const [key, value] of whenTrue.env) {
        env.set(key, mergeDependencies(env.get(key) ?? [], value));
      }
      for (const [key, value] of whenFalse.env) {
        env.set(key, mergeDependencies(env.get(key) ?? [], value));
      }
      return;
    }

    if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
      const deps = evaluateExpression(module, env, node.expression, context);
      if (ts.isVariableDeclarationList(node.initializer)) {
        for (const declaration of node.initializer.declarations) {
          assignBindingName(module, env, declaration.name, deps, context);
        }
      } else if (ts.isIdentifier(node.initializer)) {
        env.set(node.initializer.text, deps);
      }
      const body = analyzeStatementList(
        module,
        ts.isBlock(node.statement) ? node.statement.statements : [node.statement],
        env,
        context,
      );
      sinkEvents.push(...body.sinkEvents);
      returnDeps = mergeDependencies(returnDeps, body.returnDeps);
      for (const [key, value] of body.env) {
        env.set(key, mergeDependencies(env.get(key) ?? [], value));
      }
      return;
    }

    if (ts.isWhileStatement(node) || ts.isDoStatement(node)) {
      const body = analyzeStatementList(
        module,
        ts.isBlock(node.statement) ? node.statement.statements : [node.statement],
        env,
        context,
      );
      sinkEvents.push(...body.sinkEvents);
      returnDeps = mergeDependencies(
        returnDeps,
        evaluateExpression(module, env, node.expression, context),
        body.returnDeps,
      );
      for (const [key, value] of body.env) {
        env.set(key, mergeDependencies(env.get(key) ?? [], value));
      }
      return;
    }

    if (ts.isTryStatement(node)) {
      const tryResult = analyzeStatementList(module, node.tryBlock.statements, env, context);
      sinkEvents.push(...tryResult.sinkEvents);
      returnDeps = mergeDependencies(returnDeps, tryResult.returnDeps);
      for (const [key, value] of tryResult.env) {
        env.set(key, mergeDependencies(env.get(key) ?? [], value));
      }

      if (node.catchClause) {
        const catchEnv = new Map(env);
        if (
          node.catchClause.variableDeclaration &&
          ts.isIdentifier(node.catchClause.variableDeclaration.name)
        ) {
          catchEnv.set(node.catchClause.variableDeclaration.name.text, []);
        }
        const catchResult = analyzeStatementList(
          module,
          node.catchClause.block.statements,
          catchEnv,
          context,
        );
        sinkEvents.push(...catchResult.sinkEvents);
        returnDeps = mergeDependencies(returnDeps, catchResult.returnDeps);
        for (const [key, value] of catchResult.env) {
          env.set(key, mergeDependencies(env.get(key) ?? [], value));
        }
      }

      if (node.finallyBlock) {
        const finallyResult = analyzeStatementList(
          module,
          node.finallyBlock.statements,
          env,
          context,
        );
        sinkEvents.push(...finallyResult.sinkEvents);
        returnDeps = mergeDependencies(returnDeps, finallyResult.returnDeps);
        for (const [key, value] of finallyResult.env) {
          env.set(key, mergeDependencies(env.get(key) ?? [], value));
        }
      }
      return;
    }

    if (ts.isBlock(node)) {
      const nested = analyzeStatementList(module, node.statements, env, context);
      sinkEvents.push(...nested.sinkEvents);
      returnDeps = mergeDependencies(returnDeps, nested.returnDeps);
      for (const [key, value] of nested.env) {
        env.set(key, mergeDependencies(env.get(key) ?? [], value));
      }
      return;
    }

    ts.forEachChild(node, visitNode);
  };

  const visitExpression = (expression: ts.Expression): void => {
    if (
      ts.isBinaryExpression(expression) &&
      expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
    ) {
      const rightDeps = evaluateExpression(module, env, expression.right, context);
      if (ts.isIdentifier(expression.left)) {
        const deps = isTaintSourceName(expression.left.text)
          ? mergeDependencies(rightDeps, [SOURCE_TOKEN])
          : rightDeps;
        env.set(expression.left.text, deps);
      } else if (
        ts.isArrayLiteralExpression(expression.left) ||
        ts.isObjectLiteralExpression(expression.left)
      ) {
        evaluateExpression(module, env, expression.left as unknown as ts.Expression, context);
      }
      return;
    }

    if (ts.isCallExpression(expression)) {
      const directSink = getDirectSink(expression);
      const argDeps = expression.arguments.map((argument) =>
        evaluateExpression(module, env, argument, context),
      );
      const combinedArgs = mergeDependencies(...argDeps);
      if (directSink && hasDependencies(combinedArgs)) {
        sinkEvents.push(
          createSinkEvent(directSink.kind, directSink.calleeText, module, expression, combinedArgs),
        );
      }

      const summary = resolveFunctionSummary(module, expression.expression, context);
      if (summary) {
        for (const event of summary.sinkEvents) {
          const mapped = mapDependencies(event.dependencies, argDeps);
          if (hasDependencies(mapped)) {
            sinkEvents.push({ ...event, dependencies: mapped });
          }
        }
      }

      for (const argument of expression.arguments) {
        ts.forEachChild(argument, visitNode);
      }
      return;
    }

    ts.forEachChild(expression, visitNode);
  };

  for (const statement of statements) {
    visitNode(statement);
  }

  return { env, sinkEvents, returnDeps: sortDependencies(returnDeps) };
}

function analyzeFunction(
  functionInfo: FunctionInfo,
  context: ProjectAnalysisContext,
): FunctionSummary {
  const env = new Map<string, DependencyToken[]>();
  functionInfo.params.forEach((param, index) => {
    if (isTaintSourceName(param)) {
      env.set(param, [SOURCE_TOKEN]);
    } else {
      env.set(param, [`param:${index}`]);
    }
  });

  const statements =
    functionInfo.node.body && ts.isBlock(functionInfo.node.body)
      ? functionInfo.node.body.statements
      : functionInfo.node.body && ts.isExpression(functionInfo.node.body)
        ? [ts.factory.createReturnStatement(functionInfo.node.body)]
        : [];

  const analysis = analyzeStatementList(
    context.modules.get(functionInfo.filePath)!,
    statements,
    env,
    context,
  );

  return {
    returnDependencies: analysis.returnDeps,
    sinkEvents: analysis.sinkEvents,
  };
}

function analyzeTopLevelModule(
  module: ModuleInfo,
  context: ProjectAnalysisContext,
): { exports: Map<string, DependencyToken[]>; sinkEvents: SinkEvent[] } {
  const analysis = analyzeStatementList(module, module.sourceFile.statements, new Map(), context);
  const exports = new Map<string, DependencyToken[]>();

  for (const [exportName, localName] of module.exportedValues) {
    const deps = analysis.env.get(localName);
    if (deps) {
      exports.set(exportName, sortDependencies(deps));
    }
  }

  return { exports, sinkEvents: analysis.sinkEvents };
}

function buildRuleMatchers(rules: Rule[]): Map<string, RuleMatcher> {
  const matchers = new Map<string, RuleMatcher>();

  for (const rule of rules) {
    if (rule.patternType !== 'semantic_pattern') continue;

    let config: Record<string, unknown>;
    try {
      config = JSON.parse(rule.patternConfig) as Record<string, unknown>;
    } catch {
      continue;
    }

    if (Array.isArray(config.functionNames) && config.checkArguments) {
      matchers.set(rule.ruleId, {
        kind: 'log',
        functionNames: new Set(
          (config.functionNames as string[]).map((name) => name.toLowerCase()),
        ),
      });
      continue;
    }

    if (config.checkForPHIFields && config.apiContext) {
      matchers.set(rule.ruleId, { kind: 'response' });
      continue;
    }

    if (config.checkThrowContent) {
      matchers.set(rule.ruleId, { kind: 'error' });
    }
  }

  return matchers;
}

function ruleMatchesEvent(matcher: RuleMatcher, event: SinkEvent): boolean {
  if (matcher.kind !== event.kind) return false;
  if (!matcher.functionNames) return true;
  return matcher.functionNames.has(event.calleeText.toLowerCase());
}

function createFinding(rule: Rule, event: SinkEvent): ComplianceFinding {
  return {
    ruleId: rule.ruleId,
    frameworkId: 'hipaa',
    severity: rule.severity,
    category: rule.category,
    title: `Tainted PHI data used in ${event.kind} sink`,
    description: `Tainted PHI flows into ${event.calleeText}. ${rule.description}`,
    filePath: event.filePath,
    lineNumber: event.lineNumber,
    columnNumber: event.columnNumber,
    codeSnippet: event.codeSnippet,
    citation: rule.citation,
    remediation: rule.remediation,
    confidence: event.dependencies.includes(SOURCE_TOKEN) ? 'high' : 'medium',
    context:
      event.kind === 'log'
        ? 'log_statement'
        : event.kind === 'response'
          ? 'api_response'
          : 'error_handler',
    timestamp: new Date().toISOString(),
  };
}

export function analyzeProjectTaint(files: TaintFile[], rules: Rule[]): ComplianceFinding[] {
  const relevantRules = rules.filter((rule) => rule.patternType === 'semantic_pattern');
  if (relevantRules.length === 0) return [];

  const modules = buildModules(files);
  if (modules.size === 0) return [];

  const context: ProjectAnalysisContext = {
    modules,
    functionSummaries: new Map(),
    exportedValueDeps: new Map(),
  };

  for (let iteration = 0; iteration < 8; iteration++) {
    let changed = false;

    for (const module of modules.values()) {
      for (const functionInfo of module.functions.values()) {
        const key = `${module.filePath}::${functionInfo.name}`;
        const summary = analyzeFunction(functionInfo, context);
        const nextSerialized = serializeSummary(summary);
        const currentSerialized = context.functionSummaries.has(key)
          ? serializeSummary(context.functionSummaries.get(key)!)
          : '';
        if (nextSerialized !== currentSerialized) {
          context.functionSummaries.set(key, summary);
          changed = true;
        }
      }
    }

    for (const module of modules.values()) {
      const topLevel = analyzeTopLevelModule(module, context);
      const currentExports =
        context.exportedValueDeps.get(module.filePath) ?? new Map<string, DependencyToken[]>();
      const nextSerialized = JSON.stringify(
        [...topLevel.exports.entries()].sort(([a], [b]) => a.localeCompare(b)),
      );
      const currentSerialized = JSON.stringify(
        [...currentExports.entries()].sort(([a], [b]) => a.localeCompare(b)),
      );
      if (nextSerialized !== currentSerialized) {
        context.exportedValueDeps.set(module.filePath, topLevel.exports);
        changed = true;
      }
    }

    if (!changed) break;
  }

  const matchers = buildRuleMatchers(relevantRules);
  const findings: ComplianceFinding[] = [];
  const emitted = new Set<string>();

  for (const module of modules.values()) {
    const topLevel = analyzeTopLevelModule(module, context);
    const candidateEvents = [...topLevel.sinkEvents];

    for (const functionInfo of module.functions.values()) {
      const summary = context.functionSummaries.get(`${module.filePath}::${functionInfo.name}`);
      if (!summary) continue;
      for (const event of summary.sinkEvents) {
        if (event.dependencies.includes(SOURCE_TOKEN)) {
          candidateEvents.push(event);
        }
      }
    }

    for (const event of candidateEvents) {
      for (const rule of relevantRules) {
        const matcher = matchers.get(rule.ruleId);
        if (!matcher || !ruleMatchesEvent(matcher, event)) continue;
        const key = `${rule.ruleId}:${event.filePath}:${event.lineNumber}:${event.columnNumber}`;
        if (emitted.has(key)) continue;
        emitted.add(key);
        findings.push(createFinding(rule, event));
      }
    }
  }

  return findings;
}

export function analyzeTaint(filePath: string, content: string, rule: Rule): ComplianceFinding[] {
  return analyzeProjectTaint([{ filePath, content }], [rule]);
}
