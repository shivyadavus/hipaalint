Output demo.gif
Output demo.mp4

Require node

Set FontSize 18
Set Width 1200
Set Height 800
Set Padding 40
Set Theme "Dracula"
Set Framerate 30

Type "node dist/cli/index.js scan demo/demo-target.ts"
Sleep 500ms
Enter
Sleep 3s

Type "clear"
Enter
Sleep 500ms

Type "node dist/cli/index.js score demo/demo-target.ts"
Sleep 500ms
Enter
Sleep 3s

Type "node dist/cli/index.js report demo/demo-target.ts --format pdf -o demo/output/"
Sleep 500ms
Enter
Sleep 2s
