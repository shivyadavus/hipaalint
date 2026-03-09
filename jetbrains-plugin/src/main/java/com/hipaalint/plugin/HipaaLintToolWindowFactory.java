package com.hipaalint.plugin;

import com.google.gson.JsonObject;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.components.JBScrollPane;
import java.awt.BorderLayout;
import javax.swing.JButton;
import javax.swing.JEditorPane;
import javax.swing.JPanel;
import org.jetbrains.annotations.NotNull;

public final class HipaaLintToolWindowFactory implements ToolWindowFactory {
  private final HipaaLintScanner scanner = new HipaaLintScanner();

  @Override
  public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
    JEditorPane pane = new JEditorPane("text/html", "<html><body><p>Loading HipaaLint dashboard...</p></body></html>");
    pane.setEditable(false);

    JButton refresh = new JButton("Refresh");
    refresh.addActionListener(event -> pane.setText(renderDashboard(project)));

    JPanel panel = new JPanel(new BorderLayout(0, 8));
    panel.add(refresh, BorderLayout.NORTH);
    panel.add(new JBScrollPane(pane), BorderLayout.CENTER);

    pane.setText(renderDashboard(project));
    toolWindow.getContentManager().addContent(
        toolWindow.getContentManager().getFactory().createContent(panel, "Dashboard", false));
  }

  private String renderDashboard(Project project) {
    try {
      HipaaLintScanner.DashboardResult result = scanner.scanProject(project);
      JsonObject score = result.score();
      double overallScore = score.get("overallScore").getAsDouble();
      String band = score.get("band").getAsString();
      StringBuilder findings = new StringBuilder();
      for (HipaaLintFinding finding : result.findings().stream().limit(6).toList()) {
        findings.append("<li><strong>")
            .append(finding.getRuleId())
            .append("</strong> ")
            .append(finding.getTitle())
            .append("</li>");
      }
      return "<html><body style='font-family:sans-serif;padding:12px;'>"
          + "<h2>HipaaLint Dashboard</h2>"
          + "<p><strong>Score:</strong> "
          + String.format("%.1f", overallScore)
          + " ("
          + band
          + ")</p>"
          + "<h3>Findings</h3><ul>"
          + findings
          + "</ul></body></html>";
    } catch (Exception error) {
      return "<html><body style='font-family:sans-serif;padding:12px;'><h2>HipaaLint Dashboard</h2><p>"
          + error.getMessage()
          + "</p></body></html>";
    }
  }
}
