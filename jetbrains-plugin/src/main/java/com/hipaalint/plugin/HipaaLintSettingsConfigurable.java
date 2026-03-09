package com.hipaalint.plugin;

import com.intellij.openapi.options.Configurable;
import com.intellij.openapi.project.Project;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

public final class HipaaLintSettingsConfigurable implements Configurable {
  private final Project project;
  private JPanel panel;
  private JComboBox<String> frameworkBox;
  private JComboBox<String> sensitivityBox;
  private JTextField configField;
  private JTextField cliField;

  public HipaaLintSettingsConfigurable(Project project) {
    this.project = project;
  }

  @Override
  public @Nls String getDisplayName() {
    return "HipaaLint";
  }

  @Override
  public @Nullable JComponent createComponent() {
    panel = new JPanel(new GridBagLayout());
    frameworkBox = new JComboBox<>(new String[] {"hipaa", "hitrust", "soc2-health"});
    sensitivityBox = new JComboBox<>(new String[] {"strict", "balanced", "relaxed"});
    configField = new JTextField();
    cliField = new JTextField();

    addRow(0, "Framework", frameworkBox);
    addRow(1, "Sensitivity", sensitivityBox);
    addRow(2, "Config Path", configField);
    addRow(3, "CLI Path", cliField);

    reset();
    return panel;
  }

  private void addRow(int row, String label, JComponent component) {
    GridBagConstraints labelConstraints = new GridBagConstraints();
    labelConstraints.gridx = 0;
    labelConstraints.gridy = row;
    labelConstraints.anchor = GridBagConstraints.WEST;
    labelConstraints.insets.set(4, 4, 4, 12);
    panel.add(new JLabel(label), labelConstraints);

    GridBagConstraints fieldConstraints = new GridBagConstraints();
    fieldConstraints.gridx = 1;
    fieldConstraints.gridy = row;
    fieldConstraints.weightx = 1.0;
    fieldConstraints.fill = GridBagConstraints.HORIZONTAL;
    fieldConstraints.insets.set(4, 4, 4, 4);
    panel.add(component, fieldConstraints);
  }

  @Override
  public boolean isModified() {
    HipaaLintSettingsService.State state = HipaaLintSettingsService.getInstance(project).getCurrentState();
    return !state.framework.equals(frameworkBox.getSelectedItem())
        || !state.sensitivity.equals(sensitivityBox.getSelectedItem())
        || !state.configPath.equals(configField.getText())
        || !state.cliPath.equals(cliField.getText());
  }

  @Override
  public void apply() {
    HipaaLintSettingsService.State state = HipaaLintSettingsService.getInstance(project).getCurrentState();
    state.framework = (String) frameworkBox.getSelectedItem();
    state.sensitivity = (String) sensitivityBox.getSelectedItem();
    state.configPath = configField.getText().trim();
    state.cliPath = cliField.getText().trim();
  }

  @Override
  public void reset() {
    HipaaLintSettingsService.State state = HipaaLintSettingsService.getInstance(project).getCurrentState();
    frameworkBox.setSelectedItem(state.framework);
    sensitivityBox.setSelectedItem(state.sensitivity);
    configField.setText(state.configPath);
    cliField.setText(state.cliPath);
  }

  @Override
  public void disposeUIResources() {
    panel = null;
    frameworkBox = null;
    sensitivityBox = null;
    configField = null;
    cliField = null;
  }
}
