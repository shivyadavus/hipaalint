package com.hipaalint.plugin;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.jetbrains.annotations.NotNull;

public final class HipaaLintScanner {
  private final Gson gson = new Gson();

  public List<HipaaLintFinding> scanFile(Project project, VirtualFile file) throws Exception {
    JsonObject json = execute(project, List.of("scan", file.getPath(), "--json"));
    JsonArray findings = json.getAsJsonArray("findings");
    return parseFindings(findings);
  }

  public DashboardResult scanProject(Project project) throws Exception {
    JsonObject score = execute(project, List.of("score", project.getBasePath(), "--json"));
    JsonObject scan = execute(project, List.of("scan", project.getBasePath(), "--json"));
    return new DashboardResult(score, parseFindings(scan.getAsJsonArray("findings")));
  }

  private JsonObject execute(Project project, List<String> args) throws Exception {
    HipaaLintSettingsService.State settings = HipaaLintSettingsService.getInstance(project).getCurrentState();
    List<String> command = buildCommand(project, settings, args);
    GeneralCommandLine commandLine = new GeneralCommandLine(command);
    commandLine.setCharset(java.nio.charset.StandardCharsets.UTF_8);
    commandLine.withWorkDirectory(project.getBasePath());

    CapturingProcessHandler handler = new CapturingProcessHandler(commandLine);
    String stdout = handler.runProcess(120_000).getStdout().trim();
    if (stdout.isEmpty()) {
      throw new IllegalStateException("HipaaLint returned no output.");
    }
    return gson.fromJson(stdout, JsonObject.class);
  }

  private List<String> buildCommand(
      Project project,
      HipaaLintSettingsService.State settings,
      List<String> args) throws Exception {
    Path basePath = Path.of(project.getBasePath());
    Path configured = settings.cliPath.isBlank() ? null : Path.of(settings.cliPath);
    Path localBinary = basePath.resolve("node_modules/.bin/hipaalint");
    Path localScript = basePath.resolve("dist/cli/index.js");

    List<String> command = new ArrayList<>();
    if (configured != null && Files.exists(configured)) {
      appendExecutable(command, configured);
    } else if (Files.exists(localBinary)) {
      appendExecutable(command, localBinary);
    } else if (Files.exists(localScript)) {
      command.add("node");
      command.add(localScript.toString());
    } else {
      command.add("hipaalint");
    }

    command.addAll(args);
    command.add("--framework");
    command.add(settings.framework);
    command.add("--sensitivity");
    command.add(settings.sensitivity);
    if (!settings.configPath.isBlank()) {
      command.add("--config");
      command.add(settings.configPath);
    }
    return command;
  }

  private void appendExecutable(List<String> command, Path executable) {
    if (executable.toString().endsWith(".js")) {
      command.add("node");
    }
    command.add(executable.toString());
  }

  private List<HipaaLintFinding> parseFindings(JsonArray findings) {
    if (findings == null) return Collections.emptyList();

    List<HipaaLintFinding> parsed = new ArrayList<>();
    for (int i = 0; i < findings.size(); i++) {
      JsonObject finding = findings.get(i).getAsJsonObject();
      parsed.add(
          new HipaaLintFinding(
              finding.get("ruleId").getAsString(),
              finding.get("title").getAsString(),
              finding.get("remediation").getAsString(),
              finding.get("severity").getAsString(),
              finding.get("lineNumber").getAsInt(),
              finding.get("columnNumber").getAsInt()));
    }
    return parsed;
  }

  public record DashboardResult(@NotNull JsonObject score, @NotNull List<HipaaLintFinding> findings) {}
}
