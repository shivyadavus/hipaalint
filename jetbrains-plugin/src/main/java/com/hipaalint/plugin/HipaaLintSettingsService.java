package com.hipaalint.plugin;

import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.Service;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Service(Service.Level.PROJECT)
@State(name = "HipaaLintSettings", storages = @Storage("hipaalint.xml"))
public final class HipaaLintSettingsService
    implements PersistentStateComponent<HipaaLintSettingsService.State> {

  public static final class State {
    public String framework = "hipaa";
    public String sensitivity = "balanced";
    public String configPath = "";
    public String cliPath = "";
  }

  private State state = new State();

  public static HipaaLintSettingsService getInstance(Project project) {
    return project.getService(HipaaLintSettingsService.class);
  }

  @Override
  public @Nullable State getState() {
    return state;
  }

  @Override
  public void loadState(@NotNull State state) {
    this.state = state;
  }

  public State getCurrentState() {
    return state;
  }
}
