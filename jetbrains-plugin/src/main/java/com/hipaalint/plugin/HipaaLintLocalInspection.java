package com.hipaalint.plugin;

import com.intellij.codeInspection.InspectionManager;
import com.intellij.codeInspection.LocalInspectionTool;
import com.intellij.codeInspection.ProblemDescriptor;
import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.codeInspection.ProblemDescriptorBase;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiFile;
import java.util.ArrayList;
import java.util.List;
import org.jetbrains.annotations.NotNull;

public final class HipaaLintLocalInspection extends LocalInspectionTool {
  private final HipaaLintScanner scanner = new HipaaLintScanner();

  @Override
  public ProblemDescriptor @NotNull [] checkFile(
      @NotNull PsiFile file,
      @NotNull InspectionManager manager,
      boolean isOnTheFly) {
    VirtualFile virtualFile = file.getVirtualFile();
    if (virtualFile == null || virtualFile.isDirectory()) {
      return ProblemDescriptor.EMPTY_ARRAY;
    }

    String extension = virtualFile.getExtension();
    if (extension == null || !(extension.equals("ts") || extension.equals("tsx") || extension.equals("js") || extension.equals("jsx") || extension.equals("py") || extension.equals("java"))) {
      return ProblemDescriptor.EMPTY_ARRAY;
    }

    Project project = file.getProject();
    Document document = FileDocumentManager.getInstance().getDocument(virtualFile);
    if (document == null) {
      return ProblemDescriptor.EMPTY_ARRAY;
    }

    try {
      List<HipaaLintFinding> findings = scanner.scanFile(project, virtualFile);
      List<ProblemDescriptor> descriptors = new ArrayList<>();
      for (HipaaLintFinding finding : findings) {
        int line = Math.max(0, finding.getLineNumber() - 1);
        if (line >= document.getLineCount()) {
          continue;
        }
        int start = document.getLineStartOffset(line);
        int end = document.getLineEndOffset(line);
        PsiElement element = file.findElementAt(start);
        if (element == null) {
          continue;
        }
        descriptors.add(
            manager.createProblemDescriptor(
                element,
                element,
                finding.getTitle() + ": " + finding.getRemediation(),
                severityToHighlight(finding.getSeverity()),
                isOnTheFly,
                createQuickFix(finding.getRuleId())));
      }
      return descriptors.toArray(ProblemDescriptor.EMPTY_ARRAY);
    } catch (Exception ignored) {
      return ProblemDescriptor.EMPTY_ARRAY;
    }
  }

  private ProblemHighlightType severityToHighlight(String severity) {
    return switch (severity) {
      case "critical", "high" -> ProblemHighlightType.GENERIC_ERROR_OR_WARNING;
      case "medium" -> ProblemHighlightType.WARNING;
      default -> ProblemHighlightType.INFORMATION;
    };
  }

  private HipaaLintQuickFix createQuickFix(String ruleId) {
    return switch (ruleId) {
      case "HIPAA-ENC-001", "HITRUST-01.V-01", "SOC2-CC6.1-001", "HIPAA-ENC-005", "HIPAA-INF-001", "HITRUST-10.C-01" -> new HipaaLintQuickFix(ruleId);
      default -> null;
    };
  }
}
