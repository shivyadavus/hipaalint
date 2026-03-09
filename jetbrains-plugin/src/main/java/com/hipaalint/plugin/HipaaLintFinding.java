package com.hipaalint.plugin;

public final class HipaaLintFinding {
  private final String ruleId;
  private final String title;
  private final String remediation;
  private final String severity;
  private final int lineNumber;
  private final int columnNumber;

  public HipaaLintFinding(
      String ruleId,
      String title,
      String remediation,
      String severity,
      int lineNumber,
      int columnNumber) {
    this.ruleId = ruleId;
    this.title = title;
    this.remediation = remediation;
    this.severity = severity;
    this.lineNumber = lineNumber;
    this.columnNumber = columnNumber;
  }

  public String getRuleId() {
    return ruleId;
  }

  public String getTitle() {
    return title;
  }

  public String getRemediation() {
    return remediation;
  }

  public String getSeverity() {
    return severity;
  }

  public int getLineNumber() {
    return lineNumber;
  }

  public int getColumnNumber() {
    return columnNumber;
  }
}
