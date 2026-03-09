package com.hipaalint.plugin;

import com.intellij.codeInspection.LocalQuickFix;
import com.intellij.codeInspection.ProblemDescriptor;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.NotNull;

public final class HipaaLintQuickFix implements LocalQuickFix {
  private final String ruleId;

  public HipaaLintQuickFix(String ruleId) {
    this.ruleId = ruleId;
  }

  @Override
  public @Nls @NotNull String getFamilyName() {
    return switch (ruleId) {
      case "HIPAA-ENC-001", "HITRUST-01.V-01", "SOC2-CC6.1-001" -> "Upgrade to HTTPS";
      case "HIPAA-ENC-005" -> "Upgrade weak TLS version";
      case "HIPAA-INF-001", "HITRUST-10.C-01" -> "Restrict CORS origins";
      default -> "Apply HipaaLint fix";
    };
  }

  @Override
  public void applyFix(@NotNull Project project, @NotNull ProblemDescriptor descriptor) {
    Document document = descriptor.getPsiElement().getContainingFile().getViewProvider().getDocument();
    if (document == null) return;

    int line = document.getLineNumber(descriptor.getPsiElement().getTextRange().getStartOffset());
    int start = document.getLineStartOffset(line);
    int end = document.getLineEndOffset(line);
    String original = document.getText(new com.intellij.openapi.util.TextRange(start, end));
    String updated = switch (ruleId) {
      case "HIPAA-ENC-001", "HITRUST-01.V-01", "SOC2-CC6.1-001" -> original.replaceAll("http://(?!localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)", "https://");
      case "HIPAA-ENC-005" -> original.replaceAll("\\b(TLSv1_0|TLSv1_1|SSLv3|ssl3|tls1_0|tls1_1)\\b", "TLSv1_2");
      case "HIPAA-INF-001", "HITRUST-10.C-01" -> original
          .replaceAll("origin:\\s*[\"'`]\\*[\"'`]", "origin: process.env.CORS_ORIGIN")
          .replaceAll("\\bcors\\(\\s*\\)", "cors({ origin: process.env.CORS_ORIGIN })");
      default -> original;
    };

    if (!updated.equals(original)) {
      document.replaceString(start, end, updated);
    }
  }
}
