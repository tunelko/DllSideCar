global using Color = System.Windows.Media.Color;
// Aliasing MessageBox to our themed AppDialog routes every existing
// `MessageBox.Show(...)` call site through the dark-mode dialog without
// touching the 40+ callers. AppDialog.Show mirrors the MessageBox API
// exactly (same overloads, same MessageBoxResult/Button/Image enums).
global using MessageBox = DllSidecar.GUI.Views.AppDialog;
global using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
