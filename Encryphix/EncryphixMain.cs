﻿// ======================================================================================================
// Encryphix - File and Folder Encryption Software
// © Copyright 2025, Eray Türkay.
// Project Type: Open Source
// License: MIT License
// Website: https://www.turkaysoftware.com/encryphix
// GitHub: https://github.com/turkaysoftware/encryphix
// ======================================================================================================

using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
// TS MODULES
using static Encryphix.TSModules;
using static Encryphix.TSProtection;

namespace Encryphix{
    public partial class EncryphixMain : Form{
        public EncryphixMain(){
            InitializeComponent();
            CheckForIllegalCrossThreadCalls = false;
            // LANGUAGE SET MODES
            englishToolStripMenuItem.Tag = "en";
            turkishToolStripMenuItem.Tag = "tr";
            // LANGUAGE SET EVENTS
            englishToolStripMenuItem.Click += LanguageToolStripMenuItem_Click;
            turkishToolStripMenuItem.Click += LanguageToolStripMenuItem_Click;
        }
        // GLOBAL VARIABLES
        // ======================================================================================================
        public static string lang, lang_path;
        public static int theme;
        // TS PROTECTION ERROR MESSAGES
        // ======================================================================================================
        public static class TSProtectionErrorMessages{
            public static Dictionary<string, string> Messages = new Dictionary<string, string>(){
                { "FolderEncryptionError", "" },
                { "InvalidPasswordOrCorruptFile", "" },
                { "FileOpenError", "" },
                { "SaltReadError", "" },
                { "IVReadError", "" },
                { "InvalidEncryptedFileExtension", "" },
                { "AccessError", "" },
                { "UnknownError", "" },
            };
        }
        // LOCAL VARIABLES
        // ======================================================================================================
        int startup_status;
        bool p_mode, p_visible = true;
        readonly string ts_wizard_name = "TS Wizard";
        // ======================================================================================================
        // COLOR MODES
        static readonly List<Color> header_colors = new List<Color>() { Color.Transparent, Color.Transparent, Color.Transparent };
        // HEADER SETTINGS
        // ======================================================================================================
        private class HeaderMenuColors : ToolStripProfessionalRenderer{
            public HeaderMenuColors() : base(new HeaderColors()) { }
            protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e) { e.ArrowColor = header_colors[1]; base.OnRenderArrow(e); }
            protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e){
                Graphics g = e.Graphics;
                g.SmoothingMode = SmoothingMode.AntiAlias;
                float dpiScale = g.DpiX / 96f;
                // TICK BG
                // using (SolidBrush bgBrush = new SolidBrush(header_colors[0])){ RectangleF bgRect = new RectangleF( e.ImageRectangle.Left, e.ImageRectangle.Top, e.ImageRectangle.Width,e.ImageRectangle.Height); g.FillRectangle(bgBrush, bgRect); }
                using (Pen anti_alias_pen = new Pen(header_colors[2], 3 * dpiScale)){
                    Rectangle rect = e.ImageRectangle;
                    Point p1 = new Point((int)(rect.Left + 3 * dpiScale), (int)(rect.Top + rect.Height / 2));
                    Point p2 = new Point((int)(rect.Left + 7 * dpiScale), (int)(rect.Bottom - 4 * dpiScale));
                    Point p3 = new Point((int)(rect.Right - 2 * dpiScale), (int)(rect.Top + 3 * dpiScale));
                    g.DrawLines(anti_alias_pen, new Point[] { p1, p2, p3 });
                }
            }
        }
        private class HeaderColors : ProfessionalColorTable{
            public override Color MenuItemSelected => header_colors[0];
            public override Color ToolStripDropDownBackground => header_colors[0];
            public override Color ImageMarginGradientBegin => header_colors[0];
            public override Color ImageMarginGradientEnd => header_colors[0];
            public override Color ImageMarginGradientMiddle => header_colors[0];
            public override Color MenuItemSelectedGradientBegin => header_colors[0];
            public override Color MenuItemSelectedGradientEnd => header_colors[0];
            public override Color MenuItemPressedGradientBegin => header_colors[0];
            public override Color MenuItemPressedGradientMiddle => header_colors[0];
            public override Color MenuItemPressedGradientEnd => header_colors[0];
            public override Color MenuItemBorder => header_colors[0];
            public override Color CheckBackground => header_colors[0];
            public override Color ButtonSelectedBorder => header_colors[0];
            public override Color CheckSelectedBackground => header_colors[0];
            public override Color CheckPressedBackground => header_colors[0];
            public override Color MenuBorder => header_colors[0];
            public override Color SeparatorLight => header_colors[1];
            public override Color SeparatorDark => header_colors[1];
        }
        // LOAD SOFTWARE SETTINGS
        // ======================================================================================================
        private void RunSoftwareEngine(){
            // DOUBLE BUFFERS
            typeof(DataGridView).InvokeMember("DoubleBuffered", BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.SetProperty, null, FAF_DGV, new object[] { true });
            // ADD TEMPORT COLUMNS
            FAF_DGV.Columns.Add("FP", "Yol");
            FAF_DGV.Columns.Add("FP", "Boyut");
            FAF_DGV.Columns.Add("FP", "Durum");
            FAF_DGV.Columns[1].Width = 50;
            FAF_DGV.Columns[2].Width = 200;
            // NOT SORTABLE SET
            foreach (DataGridViewColumn OSD_Column in FAF_DGV.Columns){
                OSD_Column.SortMode = DataGridViewColumnSortMode.NotSortable;
            }
            FAF_DGV.ClearSelection();
            // DPI SET TEXTBOX BUTTONS
            BtnShowPassword.Height = TextBox_Password.Height + 2;
            BtnSavePath.Height = TextBox_SaveFolder.Height + 2;
            // THEME - LANG - STARTUP MODE PRELOADER
            // ======================================================================================================
            TSSettingsSave software_read_settings = new TSSettingsSave(ts_sf);
            //
            int theme_mode = int.TryParse(software_read_settings.TSReadSettings(ts_settings_container, "ThemeStatus"), out int the_status) ? the_status : 1;
            Theme_engine(theme_mode);
            darkThemeToolStripMenuItem.Checked = theme_mode == 0;
            lightThemeToolStripMenuItem.Checked = theme_mode == 1;
            string lang_mode = software_read_settings.TSReadSettings(ts_settings_container, "LanguageStatus");
            var languageFiles = new Dictionary<string, (object langResource, ToolStripMenuItem menuItem, bool fileExists)>{
                { "en", (ts_lang_en, englishToolStripMenuItem, File.Exists(ts_lang_en)) },
                { "tr", (ts_lang_tr, turkishToolStripMenuItem, File.Exists(ts_lang_tr)) },
            };
            foreach (var langLoader in languageFiles) { langLoader.Value.menuItem.Enabled = langLoader.Value.fileExists; }
            var (langResource, selectedMenuItem, _) = languageFiles.ContainsKey(lang_mode) ? languageFiles[lang_mode] : languageFiles["en"];
            Lang_engine(Convert.ToString(langResource), lang_mode);
            selectedMenuItem.Checked = true;
            //
            string startup_mode = software_read_settings.TSReadSettings(ts_settings_container, "StartupStatus");
            startup_status = int.TryParse(startup_mode, out int ini_status) && (ini_status == 0 || ini_status == 1) ? ini_status : 0;
            WindowState = startup_status == 1 ? FormWindowState.Maximized : FormWindowState.Normal;
            windowedToolStripMenuItem.Checked = startup_status == 0;
            fullScreenToolStripMenuItem.Checked = startup_status == 1;
            //
            TextBox_SaveFolder.Text = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        }
        // MAIN TOOLTIP SETTINGS
        // ======================================================================================================
        private void MainToolTip_Draw(object sender, DrawToolTipEventArgs e){ e.DrawBackground(); e.DrawBorder(); e.DrawText(); }
        // ENCRYPHIX LOAD
        // ====================================================================================================== 
        private void Encryphix_Load(object sender, EventArgs e){
            Text = TS_VersionEngine.TS_SofwareVersion(0, Program.ts_version_mode);
            HeaderMenu.Cursor = Cursors.Hand;
            RunSoftwareEngine();
            //
            Task softwareUpdateCheck = Task.Run(() => Software_update_check(0));
        }
        // FOLDER AND FILE SELECT DRAG AND DROP
        // ====================================================================================================== 
        private void Encryphix_DragEnter(object sender, DragEventArgs e){
            if (e.Data.GetDataPresent(DataFormats.FileDrop)){
                e.Effect = DragDropEffects.Copy;
            }
        }
        private void Encryphix_DragDrop(object sender, DragEventArgs e){
            if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
            var droppedPaths = (string[])e.Data.GetData(DataFormats.FileDrop);
            ProcessSelectedPaths(droppedPaths);
        }
        // FOLDER AND FILE SELECT DIALOG
        // ====================================================================================================== 
        private void BtnSelect_Click(object sender, EventArgs e){
            TSGetLangs software_lang = new TSGetLangs(lang_path);
            var selectedPaths = new List<string>();
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            // Folder Select
            using (var fbd = new FolderBrowserDialog()){
                fbd.Description = software_lang.TSReadLangs("EncryphixUI", "eui_folder_select");
                fbd.ShowNewFolderButton = false;
                fbd.SelectedPath = desktopPath;
                if (fbd.ShowDialog() == DialogResult.OK && Directory.Exists(fbd.SelectedPath)){
                    selectedPaths.Add(fbd.SelectedPath);
                }
            }
            // File Select
            using (var ofd = new OpenFileDialog()){
                ofd.Multiselect = true;
                ofd.Title = string.Format(software_lang.TSReadLangs("EncryphixUI", "eui_file_select"), Application.ProductName);
                ofd.InitialDirectory = desktopPath;
                if (ofd.ShowDialog() == DialogResult.OK && ofd.FileNames.Length > 0){
                    selectedPaths.AddRange(ofd.FileNames);
                }
            }
            if (selectedPaths.Count > 0){ ProcessSelectedPaths(selectedPaths); }
        }
        // FOLDER AND FILE SELECT MODULE
        // ====================================================================================================== 
        private void ProcessSelectedPaths(IEnumerable<string> paths){
            TSGetLangs software_lang = new TSGetLangs(lang_path);
            var selectedItems = new List<string>();
            var allFiles = new List<string>();
            foreach (var path in paths){
                if (File.Exists(path)){
                    selectedItems.Add(path);
                    allFiles.Add(path);
                }else if (Directory.Exists(path)){
                    selectedItems.Add(path);
                    allFiles.AddRange(Directory.GetFiles(path, "*.*", SearchOption.AllDirectories));
                }
            }
            bool hasAes = allFiles.Any(f => string.Equals(Path.GetExtension(f), EncryptedExtension, StringComparison.OrdinalIgnoreCase));
            bool hasNonAes = allFiles.Any(f => !string.Equals(Path.GetExtension(f), EncryptedExtension, StringComparison.OrdinalIgnoreCase));
            if (hasAes && hasNonAes){
                TS_MessageBoxEngine.TS_MessageBox(this, 2, software_lang.TSReadLangs("EncryphixUI", "eui_multi_select"));
                return;
            }
            FAF_DGV.Rows.Clear();
            foreach (var item in selectedItems.OrderBy(TS_NaturalSortKey)){
                File_select_process_function(item);
            }
            FAF_DGV.ClearSelection();
            p_mode = hasAes;
            //
            var image = (theme == 0) ? (hasAes ? Properties.Resources.ct_decrypt_dark : Properties.Resources.ct_encrypt_dark) : (hasAes ? Properties.Resources.ct_decrypt_light : Properties.Resources.ct_encrypt_light);
            TSImageRenderer(BtnBurner, image, 25, ContentAlignment.MiddleLeft);
            //
            BtnBurner.Text = hasAes ? " " + software_lang.TSReadLangs("EncryphixUI", "eui_decrypt_text") : " " + software_lang.TSReadLangs("EncryphixUI", "eui_encrypt_text");
            DragAndDropLabel.Visible = false;
        }
        // RENDER DATA
        // ======================================================================================================
        private void File_select_process_function(string path){
            TSGetLangs software_lang = new TSGetLangs(lang_path);
            double size = 0;
            string extension = "";
            if (File.Exists(path)){
                size = new FileInfo(path).Length;
                extension = Path.GetExtension(path);
            }else if (Directory.Exists(path)){
                size = Directory.GetFiles(path, "*.*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length);
            }
            int rowIndex = FAF_DGV.Rows.Add(path, TS_FormatSize(size));
            bool isEncrypted = string.Equals(extension, EncryptedExtension, StringComparison.OrdinalIgnoreCase);
            FAF_DGV.Rows[rowIndex].Cells[2].Value = isEncrypted ? software_lang.TSReadLangs("EncryphixUI", "eui_encrypted_text") : software_lang.TSReadLangs("EncryphixUI", "eui_decrypted_text");
        }
        // MESSAGE SEMAPHORE
        // ======================================================================================================
        private readonly SemaphoreSlim messageSemaphore = new SemaphoreSlim(1, 1);
        private async Task<DialogResult> ShowMessageBoxAsync(int mode, string message, string title = ""){
            await messageSemaphore.WaitAsync();
            try{
                return TS_MessageBoxEngine.TS_MessageBox(this, mode, message, title);
            }
            finally{
                messageSemaphore.Release();
            }
        }
        // ENCRYPT AND DECRYPT START BTN
        // ======================================================================================================
        private void BtnBurner_Click(object sender, EventArgs e){
            Super_pursuit_mode();
        }
        // ENCRYPT AND DECRYPT PURSUIT MODE
        // ======================================================================================================
        private void Super_pursuit_mode(){
            TSGetLangs softwareLang = new TSGetLangs(lang_path);
            try{
                List<string> selectedFilePaths = new List<string>();
                foreach (DataGridViewRow dataRow in FAF_DGV.Rows){
                    if (dataRow.IsNewRow) continue;
                    string filePath = dataRow.Cells[0].Value?.ToString();
                    if (!string.IsNullOrEmpty(filePath)){ selectedFilePaths.Add(filePath); }
                }
                if (selectedFilePaths.Count == 0){
                    string msg = p_mode ? softwareLang.TSReadLangs("EncryphixUI", "eui_select_file") : softwareLang.TSReadLangs("EncryphixUI", "eui_import_file");
                    _ = ShowMessageBoxAsync(2, msg);
                    return;
                }
                string password = TextBox_Password.Text.Trim();
                if (string.IsNullOrEmpty(password)){
                    _ = ShowMessageBoxAsync(2, softwareLang.TSReadLangs("EncryphixUI", "eui_input_password"));
                    return;
                }
                string outputDirectory = TextBox_SaveFolder.Text.Trim();
                if (string.IsNullOrEmpty(outputDirectory)){
                    _ = ShowMessageBoxAsync(2, softwareLang.TSReadLangs("EncryphixUI", "eui_target_folder"));
                    return;
                }
                if (!Directory.Exists(outputDirectory)){
                    _ = ShowMessageBoxAsync(2, softwareLang.TSReadLangs("EncryphixUI", "eui_target_valid_folder"));
                    return;
                }
                bool deleteOriginal = CheckOrjFileDelete.Checked;
                if (!p_mode && deleteOriginal){
                    DialogResult result = TS_MessageBoxEngine.TS_MessageBox(this, 6, string.Format(softwareLang.TSReadLangs("EncryphixUI", "eui_encrypted_warning"), "\n\n"));
                    if (result != DialogResult.Yes) return;
                }
                //
                UpdateProgressBar(0);
                Progress_BG.Visible = true;
                //
                Task.Run(async () =>{
                    try{
                        int totalFileCount = selectedFilePaths.Count;
                        int completedFileCount = 0;
                        object progressLock = new object();
                        int maxParallelTasks = 3;
                        //
                        using (SemaphoreSlim concurrencySemaphore = new SemaphoreSlim(maxParallelTasks)){
                            var parallelTasks = new List<Task>();
                            for (int i = 0; i < selectedFilePaths.Count; i++){
                                string currentFilePath = selectedFilePaths[i];
                                await concurrencySemaphore.WaitAsync();
                                var parallelTask = Task.Run(async () =>{
                                    try{
                                        if (!p_mode){
                                            // Encryption
                                            if (Directory.Exists(currentFilePath)){
                                                string zipPath = Path.Combine(outputDirectory, Path.GetFileName(currentFilePath) + ZipExtension);
                                                string encryptedPath = zipPath + EncryptedExtension;
                                                //
                                                if (File.Exists(encryptedPath)){
                                                    var result = await ShowMessageBoxAsync(6, string.Format(softwareLang.TSReadLangs("EncryphixUI", "eui_file_already_exists"), encryptedPath, "\n\n"));
                                                    if (result == DialogResult.No) return;
                                                    SafeDeleteFile(encryptedPath);
                                                }
                                                EncryptFolder(currentFilePath, password, outputDirectory, null, deleteOriginal);
                                            }else if (File.Exists(currentFilePath)){
                                                string encryptedFilePath = Path.Combine(outputDirectory, Path.GetFileName(currentFilePath) + EncryptedExtension);
                                                //
                                                if (File.Exists(encryptedFilePath)){
                                                    var result = await ShowMessageBoxAsync(6, string.Format(softwareLang.TSReadLangs("EncryphixUI", "eui_file_already_exists"), encryptedFilePath, "\n\n"));
                                                    if (result == DialogResult.No) return;
                                                    SafeDeleteFile(encryptedFilePath);
                                                }
                                                EncryptFile(currentFilePath, encryptedFilePath, password, null, deleteOriginal);
                                            }else{
                                                throw new FileNotFoundException(string.Format(softwareLang.TSReadLangs("EncryphixUI", "eui_file_and_folder_not_found"), currentFilePath));
                                            }
                                        }else{
                                            // Decryption
                                            if (!File.Exists(currentFilePath)){
                                                throw new FileNotFoundException(string.Format(softwareLang.TSReadLangs("EncryphixUI", "eui_encrypted_file_not_found"), currentFilePath));
                                            }
                                            //
                                            if (Path.GetExtension(currentFilePath).Equals(EncryptedExtension, StringComparison.OrdinalIgnoreCase)){
                                                if (currentFilePath.EndsWith(ZipExtension + EncryptedExtension, StringComparison.OrdinalIgnoreCase)){
                                                    string folderName = Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(currentFilePath));
                                                    string outputFolder = Path.Combine(outputDirectory, folderName);
                                                    //
                                                    if (Directory.Exists(outputFolder)){
                                                        var result = await ShowMessageBoxAsync(6, string.Format(softwareLang.TSReadLangs("EncryphixUI", "eui_folder_already_exists"), outputFolder, "\n\n"));
                                                        if (result == DialogResult.No) return;
                                                        SafeDeleteDirectory(outputFolder);
                                                    }
                                                    Directory.CreateDirectory(outputFolder);
                                                    DecryptFileToFolder(currentFilePath, outputFolder, password, null);
                                                }else{
                                                    string outputFile = Path.Combine(outputDirectory, Path.GetFileNameWithoutExtension(currentFilePath));
                                                    if (File.Exists(outputFile)){
                                                        var result = await ShowMessageBoxAsync(6, string.Format(softwareLang.TSReadLangs("EncryphixUI", "eui_file_already_exists"), outputFile, "\n\n"));
                                                        if (result == DialogResult.No) return;
                                                        SafeDeleteFile(outputFile);
                                                    }
                                                    DecryptFileDirect(currentFilePath, outputFile, password, null);
                                                }
                                            }
                                        }
                                        //
                                        lock (progressLock){
                                            completedFileCount++;
                                            int progress = (int)Math.Floor((completedFileCount * 100.0) / totalFileCount);
                                            if (progress > 100) progress = 100;
                                            //
                                            Invoke(new Action(() =>{
                                                UpdateProgressBar(progress);
                                                Text = $"{TS_VersionEngine.TS_SofwareVersion(0, Program.ts_version_mode)} - {(p_mode ? softwareLang.TSReadLangs("EncryphixUI", "eui_decrypted_process") : softwareLang.TSReadLangs("EncryphixUI", "eui_encrypted_process"))} {progress}%";
                                            }));
                                        }
                                    }
                                    finally{
                                        concurrencySemaphore.Release();
                                    }
                                });
                                parallelTasks.Add(parallelTask);
                            }
                            await Task.WhenAll(parallelTasks);
                        }
                        //
                        Invoke(new Action(() =>{
                            FAF_DGV.Rows.Clear();
                            DragAndDropLabel.Visible = true;
                            Progress_BG.Visible = false;
                            TextBox_Password.Text = string.Empty;
                            TextBox_SaveFolder.Text = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                            UpdateProgressBar(0);
                            Text = TS_VersionEngine.TS_SofwareVersion(0, Program.ts_version_mode);
                            _ = ShowMessageBoxAsync(1, p_mode ? softwareLang.TSReadLangs("EncryphixUI", "eui_decrypt_success") : softwareLang.TSReadLangs("EncryphixUI", "eui_encrypt_success"));
                        }));
                    }catch (Exception ex){
                        Invoke(new Action(() =>{
                            Progress_BG.Visible = false;
                            UpdateProgressBar(0);
                            string msg = ex is InvalidDataException ? string.Format(softwareLang.TSReadLangs("EncryphixUI", "eui_failed_pass_and_broken_file"), "\n") : string.Format(softwareLang.TSReadLangs("EncryphixUI", "eui_failed_process"), ex.Message);
                            _ = ShowMessageBoxAsync(3, msg);
                        }));
                    }
                });
            }catch (Exception){ }
        }
        // UPDATE PROGRESS
        // ======================================================================================================
        private void UpdateProgressBar(int percent){
            percent = Math.Max(0, Math.Min(100, percent));
            int bgWidth = Progress_BG.Width;
            Progress_FE.Width = (bgWidth * percent) / 100;
        }
        // SHOW PASSWORD
        // ======================================================================================================
        private void BtnShowPassword_Click(object sender, EventArgs e){
            TSGetLangs software_lang = new TSGetLangs(lang_path);
            p_visible = !p_visible;
            TextBox_Password.UseSystemPasswordChar = p_visible;
            MainToolTip.SetToolTip(BtnShowPassword, p_visible ? software_lang.TSReadLangs("EncryphixGraphics", "eg_password_show_hover") : software_lang.TSReadLangs("EncryphixGraphics", "eg_password_hide_hover"));
            TSImageRenderer(BtnShowPassword, theme == 0 ? (p_visible ? Properties.Resources.ct_hide_password_dark : Properties.Resources.ct_show_password_dark) : (p_visible ? Properties.Resources.ct_hide_password_light : Properties.Resources.ct_show_password_light), 10, ContentAlignment.MiddleCenter);
        }
        // SAVE LOCATION SET BTN
        // ======================================================================================================
        private void BtnSavePath_Click(object sender, EventArgs e){
            TSGetLangs software_lang = new TSGetLangs(lang_path);
            using (FolderBrowserDialog folderDialog = new FolderBrowserDialog()){
                folderDialog.Description = software_lang.TSReadLangs("EncryphixUI", "eui_target_folder_save");
                folderDialog.ShowNewFolderButton = true;
                if (folderDialog.ShowDialog() == DialogResult.OK){
                    TextBox_SaveFolder.Text = folderDialog.SelectedPath;
                }
            }
        }
        // THEME MODE
        // ======================================================================================================
        private void Select_theme_active(object target_theme){
            ToolStripMenuItem selected_theme = null;
            Select_theme_deactive();
            if (target_theme != null){
                if (selected_theme != (ToolStripMenuItem)target_theme){
                    selected_theme = (ToolStripMenuItem)target_theme;
                    selected_theme.Checked = true;
                }
            }
        }
        private void Select_theme_deactive(){
            foreach (ToolStripMenuItem disabled_theme in themeToolStripMenuItem.DropDownItems){
                disabled_theme.Checked = false;
            }
        }
        private void LightThemeToolStripMenuItem_Click(object sender, EventArgs e){
            if (theme != 1){ Theme_engine(1); Select_theme_active(sender); }
        }
        private void DarkThemeToolStripMenuItem_Click(object sender, EventArgs e){
            if (theme != 0){ Theme_engine(0); Select_theme_active(sender); }
        }
        // THEME ENGINE
        // ======================================================================================================
        private void Theme_engine(int ts){
            try{
                theme = ts;
                //
                TSSetWindowTheme(Handle, theme);
                //
                if (theme == 1){
                    // SETTINGS
                    TSImageRenderer(settingsToolStripMenuItem, Properties.Resources.tm_settings_light, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(themeToolStripMenuItem, Properties.Resources.tm_theme_light, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(languageToolStripMenuItem, Properties.Resources.tm_language_light, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(startupToolStripMenuItem, Properties.Resources.tm_startup_light, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(checkForUpdateToolStripMenuItem, Properties.Resources.tm_update_light, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(tSWizardToolStripMenuItem, Properties.Resources.tm_ts_wizard_light, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(bmacToolStripMenuItem, Properties.Resources.tm_bmac_light, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(aboutToolStripMenuItem, Properties.Resources.tm_about_light, 0, ContentAlignment.MiddleRight);
                    //
                    TSImageRenderer(BtnShowPassword, p_visible ? Properties.Resources.ct_hide_password_light : Properties.Resources.ct_show_password_light, 10, ContentAlignment.MiddleCenter);
                    TSImageRenderer(BtnSavePath, Properties.Resources.ct_folder_light, 12, ContentAlignment.MiddleCenter);
                    //
                    TSImageRenderer(BtnSelect, Properties.Resources.ct_folder_light, 27, ContentAlignment.MiddleLeft);
                    TSImageRenderer(BtnBurner, p_mode ? Properties.Resources.ct_decrypt_light : Properties.Resources.ct_encrypt_light, 27, ContentAlignment.MiddleLeft);
                }else if (theme == 0){
                    // SETTINGS
                    TSImageRenderer(settingsToolStripMenuItem, Properties.Resources.tm_settings_dark, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(themeToolStripMenuItem, Properties.Resources.tm_theme_dark, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(languageToolStripMenuItem, Properties.Resources.tm_language_dark, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(startupToolStripMenuItem, Properties.Resources.tm_startup_dark, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(checkForUpdateToolStripMenuItem, Properties.Resources.tm_update_dark, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(tSWizardToolStripMenuItem, Properties.Resources.tm_ts_wizard_dark, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(bmacToolStripMenuItem, Properties.Resources.tm_bmac_dark, 0, ContentAlignment.MiddleRight);
                    TSImageRenderer(aboutToolStripMenuItem, Properties.Resources.tm_about_dark, 0, ContentAlignment.MiddleRight);
                    //
                    TSImageRenderer(BtnShowPassword, p_visible ? Properties.Resources.ct_hide_password_dark : Properties.Resources.ct_show_password_dark, 10, ContentAlignment.MiddleCenter);
                    TSImageRenderer(BtnSavePath, Properties.Resources.ct_folder_dark, 12, ContentAlignment.MiddleCenter);
                    //
                    TSImageRenderer(BtnSelect, Properties.Resources.ct_folder_dark, 27, ContentAlignment.MiddleLeft);
                    TSImageRenderer(BtnBurner, p_mode ? Properties.Resources.ct_decrypt_dark : Properties.Resources.ct_encrypt_dark, 27, ContentAlignment.MiddleLeft);
                }
                // HEADER
                header_colors[0] = TS_ThemeEngine.ColorMode(theme, "HeaderBGColorMain");
                header_colors[1] = TS_ThemeEngine.ColorMode(theme, "HeaderFEColorMain");
                header_colors[2] = TS_ThemeEngine.ColorMode(theme, "AccentColor");
                HeaderMenu.Renderer = new HeaderMenuColors();
                // TOOLTIP
                MainToolTip.ForeColor = TS_ThemeEngine.ColorMode(theme, "HeaderFEColor");
                MainToolTip.BackColor = TS_ThemeEngine.ColorMode(theme, "HeaderBGColor");
                // HEADER MENU
                var bg = TS_ThemeEngine.ColorMode(theme, "HeaderBGColor");
                var fg = TS_ThemeEngine.ColorMode(theme, "HeaderFEColor");
                HeaderMenu.ForeColor = fg;
                HeaderMenu.BackColor = bg;
                SetMenuStripColors(HeaderMenu, bg, fg);
                // UI
                BackColor = TS_ThemeEngine.ColorMode(theme, "UIBGColor2");
                //
                FAF_DGV.BackgroundColor = TS_ThemeEngine.ColorMode(theme, "DataGridBGColor");
                FAF_DGV.GridColor = TS_ThemeEngine.ColorMode(theme, "DataGridColor");
                FAF_DGV.DefaultCellStyle.BackColor = TS_ThemeEngine.ColorMode(theme, "DataGridBGColor");
                FAF_DGV.DefaultCellStyle.ForeColor = TS_ThemeEngine.ColorMode(theme, "DataGridFEColor");
                FAF_DGV.AlternatingRowsDefaultCellStyle.BackColor = TS_ThemeEngine.ColorMode(theme, "DataGridAlternatingColor");
                FAF_DGV.ColumnHeadersDefaultCellStyle.BackColor = TS_ThemeEngine.ColorMode(theme, "AccentColor");
                FAF_DGV.ColumnHeadersDefaultCellStyle.SelectionBackColor = TS_ThemeEngine.ColorMode(theme, "AccentColor");
                FAF_DGV.ColumnHeadersDefaultCellStyle.ForeColor = TS_ThemeEngine.ColorMode(theme, "DataGridSelectionColor");
                FAF_DGV.DefaultCellStyle.SelectionBackColor = TS_ThemeEngine.ColorMode(theme, "AccentColor");
                FAF_DGV.DefaultCellStyle.SelectionForeColor = TS_ThemeEngine.ColorMode(theme, "DataGridSelectionColor");
                //
                DragAndDropLabel.BackColor = TS_ThemeEngine.ColorMode(theme, "UIBGColor2");
                DragAndDropLabel.ForeColor = TS_ThemeEngine.ColorMode(theme, "AccentColorText");
                //
                Progress_BG.BackColor = TS_ThemeEngine.ColorMode(theme, "UIBGColor");
                Progress_FE.BackColor = TS_ThemeEngine.ColorMode(theme, "AccentColor");
                //
                PanelControl.BackColor = TS_ThemeEngine.ColorMode(theme, "UIBGColor");
                //
                Label_Password.ForeColor = TS_ThemeEngine.ColorMode(theme, "AccentColorText");
                TextBox_Password.BackColor = TS_ThemeEngine.ColorMode(theme, "TextBoxBGColor");
                TextBox_Password.ForeColor = TS_ThemeEngine.ColorMode(theme, "TextBoxFEColor");
                Label_SaveFolder.ForeColor = TS_ThemeEngine.ColorMode(theme, "AccentColorText");
                CheckOrjFileDelete.ForeColor = TS_ThemeEngine.ColorMode(theme, "AccentColorText");
                TextBox_SaveFolder.BackColor = TS_ThemeEngine.ColorMode(theme, "TextBoxBGColor");
                TextBox_SaveFolder.ForeColor = TS_ThemeEngine.ColorMode(theme, "TextBoxFEColor");
                //
                var combinedBtnsControls = PanelBtns.Controls.Cast<Control>().Concat(PanelControl.Controls.Cast<Control>());
                foreach (Control control in combinedBtnsControls){
                    if (control is Button button){
                        button.ForeColor = TS_ThemeEngine.ColorMode(theme, "DynamicThemeActiveBtnBG");
                        button.BackColor = TS_ThemeEngine.ColorMode(theme, "AccentColor");
                        button.FlatAppearance.BorderColor = TS_ThemeEngine.ColorMode(theme, "AccentColor");
                        button.FlatAppearance.MouseDownBackColor = TS_ThemeEngine.ColorMode(theme, "AccentColor");
                        button.FlatAppearance.MouseOverBackColor = TS_ThemeEngine.ColorMode(theme, "AccentColorHover");
                    }
                }
                Software_other_page_preloader();
                // SAVE CURRENT THEME
                try{
                    TSSettingsSave software_setting_save = new TSSettingsSave(ts_sf);
                    software_setting_save.TSWriteSettings(ts_settings_container, "ThemeStatus", Convert.ToString(ts));
                }catch (Exception){ }
            }catch (Exception){ }
        }
        private void SetMenuStripColors(MenuStrip menuStrip, Color bgColor, Color fgColor){
            if (menuStrip == null) return;
            foreach (ToolStripItem item in menuStrip.Items){
                if (item is ToolStripMenuItem menuItem){
                    SetMenuItemColors(menuItem, bgColor, fgColor);
                }
            }
        }
        private void SetMenuItemColors(ToolStripMenuItem menuItem, Color bgColor, Color fgColor){
            if (menuItem == null) return;
            menuItem.BackColor = bgColor;
            menuItem.ForeColor = fgColor;
            foreach (ToolStripItem item in menuItem.DropDownItems){
                if (item is ToolStripMenuItem subMenuItem){
                    SetMenuItemColors(subMenuItem, bgColor, fgColor);
                }
            }
        }
        private void SetContextMenuColors(ContextMenuStrip contextMenu, Color bgColor, Color fgColor){
            if (contextMenu == null) return;
            foreach (ToolStripItem item in contextMenu.Items){
                if (item is ToolStripMenuItem menuItem){
                    SetMenuItemColors(menuItem, bgColor, fgColor);
                }
            }
        }
        private void Software_other_page_preloader(){
            // SOFTWARE ABOUT
            try{
                EncryphixAbout software_about = new EncryphixAbout();
                string software_about_name = "encryphix_about";
                software_about.Name = software_about_name;
                if (Application.OpenForms[software_about_name] != null){
                    software_about = (EncryphixAbout)Application.OpenForms[software_about_name];
                    software_about.About_preloader();
                }
            }catch (Exception){ }
        }
        // LANG MODE
        // ======================================================================================================
        private void Select_lang_active(object target_lang){
            ToolStripMenuItem selected_lang = null;
            Select_lang_deactive();
            if (target_lang != null){
                if (selected_lang != (ToolStripMenuItem)target_lang){
                    selected_lang = (ToolStripMenuItem)target_lang;
                    selected_lang.Checked = true;
                }
            }
        }
        private void Select_lang_deactive(){
            foreach (ToolStripMenuItem disabled_lang in languageToolStripMenuItem.DropDownItems){
                disabled_lang.Checked = false;
            }
        }
        private void LanguageToolStripMenuItem_Click(object sender, EventArgs e){
            if (sender is ToolStripMenuItem menuItem && menuItem.Tag is string langCode){
                if (lang != langCode && AllLanguageFiles.ContainsKey(langCode)){
                    Lang_preload(AllLanguageFiles[langCode], langCode);
                    Select_lang_active(sender);
                }
            }
        }
        private void Lang_preload(string lang_type, string lang_code){
            Lang_engine(lang_type, lang_code);
            try{
                TSSettingsSave software_setting_save = new TSSettingsSave(ts_sf);
                software_setting_save.TSWriteSettings(ts_settings_container, "LanguageStatus", lang_code);
            }catch (Exception){ }
            // LANG CHANGE NOTIFICATION
            TSGetLangs software_lang = new TSGetLangs(lang_path);
            DialogResult lang_change_message = TS_MessageBoxEngine.TS_MessageBox(this, 5, string.Format(software_lang.TSReadLangs("LangChange", "lang_change_notification"), "\n\n", "\n\n"));
            if (lang_change_message == DialogResult.Yes) { Application.Restart(); }
        }
        private void Lang_engine(string lang_type, string lang_code){
            try{
                lang_path = lang_type;
                lang = lang_code;
                // GLOBAL ENGINE
                TSGetLangs software_lang = new TSGetLangs(lang_path);
                // PROTECTION ERRORS
                TSProtectionErrorMessages.Messages["FolderEncryptionError"] = software_lang.TSReadLangs("TSProtection", "tsp_folder_encryption_error");
                TSProtectionErrorMessages.Messages["InvalidPasswordOrCorruptFile"] = software_lang.TSReadLangs("TSProtection", "tsp_invalid_password_or_corrupt_file");
                TSProtectionErrorMessages.Messages["FileOpenError"] = software_lang.TSReadLangs("TSProtection", "tsp_file_open_error");
                TSProtectionErrorMessages.Messages["SaltReadError"] = software_lang.TSReadLangs("TSProtection", "tsp_salt_read_error");
                TSProtectionErrorMessages.Messages["IVReadError"] = software_lang.TSReadLangs("TSProtection", "tsp_iv_read_error");
                TSProtectionErrorMessages.Messages["InvalidEncryptedFileExtension"] = software_lang.TSReadLangs("TSProtection", "tsp_invalid_encrypted_file_extension");
                TSProtectionErrorMessages.Messages["AccessError"] = software_lang.TSReadLangs("TSProtection", "tsp_access_error");
                TSProtectionErrorMessages.Messages["UnknownError"] = software_lang.TSReadLangs("TSProtection", "tsp_unknown_error");
                // SETTINGS
                settingsToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderMenu", "header_menu_settings");
                // THEMES
                themeToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderMenu", "header_menu_theme");
                lightThemeToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderThemes", "theme_light");
                darkThemeToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderThemes", "theme_dark");
                // LANGS
                languageToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderMenu", "header_menu_language");
                englishToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderLangs", "lang_en");
                turkishToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderLangs", "lang_tr");
                // STARTUP MODE
                startupToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderMenu", "header_menu_start");
                windowedToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderViewMode", "header_viev_mode_windowed");
                fullScreenToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderViewMode", "header_viev_mode_full_screen");
                // UPDATE
                checkForUpdateToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderMenu", "header_menu_update");
                // TS WIZARD
                tSWizardToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderMenu", "header_menu_ts_wizard");
                // BMAC
                bmacToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderMenu", "header_menu_bmac");
                // ABOUT
                aboutToolStripMenuItem.Text = software_lang.TSReadLangs("HeaderMenu", "header_menu_about");
                // UI
                FAF_DGV.Columns[0].HeaderText = software_lang.TSReadLangs("EncryphixGraphics", "eg_faf_path");
                FAF_DGV.Columns[1].HeaderText = software_lang.TSReadLangs("EncryphixGraphics", "eg_faf_size");
                FAF_DGV.Columns[2].HeaderText = software_lang.TSReadLangs("EncryphixGraphics", "eg_faf_status");
                //
                DragAndDropLabel.Text = software_lang.TSReadLangs("EncryphixGraphics", "eg_middle");
                BtnSelect.Text = " " + software_lang.TSReadLangs("EncryphixGraphics", "eg_select");
                Label_Password.Text = software_lang.TSReadLangs("EncryphixGraphics", "eg_password_label");
                Label_SaveFolder.Text = software_lang.TSReadLangs("EncryphixGraphics", "eg_saved_folder_label");
                CheckOrjFileDelete.Text = software_lang.TSReadLangs("EncryphixGraphics", "eg_saved_orj_file_label");
                //
                BtnBurner.Text = p_mode ? " " + software_lang.TSReadLangs("EncryphixUI", "eui_decrypt_text") : " " + software_lang.TSReadLangs("EncryphixUI", "eui_encrypt_text");
                //
                MainToolTip.RemoveAll();
                MainToolTip.SetToolTip(BtnShowPassword, p_visible ? software_lang.TSReadLangs("EncryphixGraphics", "eg_password_show_hover") : software_lang.TSReadLangs("EncryphixGraphics", "eg_password_hide_hover"));
                MainToolTip.SetToolTip(BtnSavePath, software_lang.TSReadLangs("EncryphixGraphics", "eg_saved_folder_hover"));
                MainToolTip.SetToolTip(CheckOrjFileDelete, software_lang.TSReadLangs("EncryphixGraphics", "eg_saved_orj_file_hover"));
            }catch (Exception){ }
        }
        // STARTUP SETINGS
        // ======================================================================================================
        private void Select_startup_mode_active(object target_startup_mode){
            ToolStripMenuItem selected_startup_mode = null;
            Select_startup_mode_deactive();
            if (target_startup_mode != null){
                if (selected_startup_mode != (ToolStripMenuItem)target_startup_mode){
                    selected_startup_mode = (ToolStripMenuItem)target_startup_mode;
                    selected_startup_mode.Checked = true;
                }
            }
        }
        private void Select_startup_mode_deactive(){
            foreach (ToolStripMenuItem disabled_startup in startupToolStripMenuItem.DropDownItems){
                disabled_startup.Checked = false;
            }
        }
        private void WindowedToolStripMenuItem_Click(object sender, EventArgs e){
            if (startup_status != 0){ startup_status = 0; Startup_mode_settings("0"); Select_startup_mode_active(sender); }
        }
        private void FullScreenToolStripMenuItem_Click(object sender, EventArgs e){
            if (startup_status != 1){ startup_status = 1; Startup_mode_settings("1"); Select_startup_mode_active(sender); }
        }
        private void Startup_mode_settings(string get_startup_value){
            try{
                TSSettingsSave software_setting_save = new TSSettingsSave(ts_sf);
                software_setting_save.TSWriteSettings(ts_settings_container, "StartupStatus", get_startup_value);
            }catch (Exception){ }
        }
        // SOFTWARE OPERATION CONTROLLER MODULE
        // ======================================================================================================
        private static bool Software_operation_controller(string __target_software_path){
            var exeFiles = Directory.GetFiles(__target_software_path, "*.exe");
            var runned_process = Process.GetProcesses();
            foreach (var exe_path in exeFiles){
                string exe_name = Path.GetFileNameWithoutExtension(exe_path);
                if (runned_process.Any(p => {
                    try{
                        return string.Equals(p.ProcessName, exe_name, StringComparison.OrdinalIgnoreCase);
                    }catch{
                        return false;
                    }
                })){
                    return true;
                }
            }
            return false;
        }
        // TS WIZARD STARTER MODE
        // ======================================================================================================
        private string[] Ts_wizard_starter_mode(){
            string[] ts_wizard_exe_files = { "TSWizard_arm64.exe", "TSWizard_x64.exe", "TSWizard.exe" };
            if (RuntimeInformation.OSArchitecture == Architecture.Arm64){
                return new[] { ts_wizard_exe_files[0], ts_wizard_exe_files[1], ts_wizard_exe_files[2] }; // arm64 > x64 > default
            }else if (Environment.Is64BitOperatingSystem){
                return new[] { ts_wizard_exe_files[1], ts_wizard_exe_files[0], ts_wizard_exe_files[2] }; // x64 > arm64 > default
            }else{
                return new[] { ts_wizard_exe_files[2], ts_wizard_exe_files[1], ts_wizard_exe_files[0] }; // default > x64 > arm64
            }
        }
        // UPDATE CHECK ENGINE
        // ======================================================================================================
        private void CheckForUpdateToolStripMenuItem_Click(object sender, EventArgs e){
            Software_update_check(1);
        }
        public void Software_update_check(int _check_update_ui){
            try{
                TSGetLangs software_lang = new TSGetLangs(lang_path);
                if (!IsNetworkCheck()){
                    if (_check_update_ui == 1){
                        TS_MessageBoxEngine.TS_MessageBox(this, 2, string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_not_connection"), "\n\n"), string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_title"), Application.ProductName));
                    }
                    return;
                }
                using (WebClient webClient = new WebClient()){
                    string client_version = TS_VersionEngine.TS_SofwareVersion(2, Program.ts_version_mode).Trim();
                    int client_num_version = Convert.ToInt32(client_version.Replace(".", string.Empty));
                    //
                    string[] version_content = webClient.DownloadString(TS_LinkSystem.github_link_lv).Split('=');
                    string last_version = version_content[1].Trim();
                    int last_num_version = Convert.ToInt32(last_version.Replace(".", string.Empty));
                    //
                    if (client_num_version < last_num_version){
                        try{
                            string baseDir = Path.Combine(Directory.GetParent(Directory.GetParent(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)).FullName).FullName);
                            string ts_wizard_path = Ts_wizard_starter_mode().Select(name => Path.Combine(baseDir, name)).FirstOrDefault(File.Exists);
                            //
                            if (ts_wizard_path != null){
                                if (!Software_operation_controller(Path.GetDirectoryName(ts_wizard_path))){
                                    // Update available
                                    DialogResult info_update = TS_MessageBoxEngine.TS_MessageBox(this, 5, string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_available_ts_wizard"), Application.ProductName, "\n\n", client_version, "\n", last_version, "\n\n", ts_wizard_name), string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_title"), Application.ProductName));
                                    if (info_update == DialogResult.Yes){
                                        Process.Start(new ProcessStartInfo { FileName = ts_wizard_path, WorkingDirectory = Path.GetDirectoryName(ts_wizard_path) });
                                    }
                                }else{
                                    TS_MessageBoxEngine.TS_MessageBox(this, 1, string.Format(software_lang.TSReadLangs("HeaderHelp", "header_help_info_notification"), ts_wizard_name));
                                }
                            }else{
                                // Update available
                                DialogResult info_update = TS_MessageBoxEngine.TS_MessageBox(this, 5, string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_available"), Application.ProductName, "\n\n", client_version, "\n", last_version, "\n\n"), string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_title"), Application.ProductName));
                                if (info_update == DialogResult.Yes){
                                    Process.Start(new ProcessStartInfo(TS_LinkSystem.github_link_lr) { UseShellExecute = true });
                                }
                            }
                        }catch (Exception){ }
                    }else if (_check_update_ui == 1 && client_num_version == last_num_version){
                        // No update available
                        TS_MessageBoxEngine.TS_MessageBox(this, 1, string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_not_available"), Application.ProductName, "\n", client_version), string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_title"), Application.ProductName));
                    }else if (_check_update_ui == 1 && client_num_version > last_num_version){
                        // Access before public use
                        TS_MessageBoxEngine.TS_MessageBox(this, 1, string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_newer"), "\n\n", string.Format("v{0}", client_version)), string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_title"), Application.ProductName));
                    }
                }
            }catch (Exception ex){
                TSGetLangs software_lang = new TSGetLangs(lang_path);
                TS_MessageBoxEngine.TS_MessageBox(this, 3, string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_error"), "\n\n", ex.Message), string.Format(software_lang.TSReadLangs("SoftwareUpdate", "su_title"), Application.ProductName));
            }
        }
        // TS WIZARD
        // ======================================================================================================
        private void TSWizardToolStripMenuItem_Click(object sender, EventArgs e){
            try{
                string baseDir = Path.Combine(Directory.GetParent(Directory.GetParent(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)).FullName).FullName);
                string ts_wizard_path = Ts_wizard_starter_mode().Select(name => Path.Combine(baseDir, name)).FirstOrDefault(File.Exists);
                //
                TSGetLangs software_lang = new TSGetLangs(lang_path);
                //
                if (ts_wizard_path != null){
                    if (!Software_operation_controller(Path.GetDirectoryName(ts_wizard_path))){
                        Process.Start(new ProcessStartInfo { FileName = ts_wizard_path, WorkingDirectory = Path.GetDirectoryName(ts_wizard_path) });
                    }else{
                        TS_MessageBoxEngine.TS_MessageBox(this, 1, string.Format(software_lang.TSReadLangs("HeaderHelp", "header_help_info_notification"), ts_wizard_name));
                    }
                }else{
                    DialogResult ts_wizard_query = TS_MessageBoxEngine.TS_MessageBox(this, 5, string.Format(software_lang.TSReadLangs("TSWizard", "tsw_content"), software_lang.TSReadLangs("HeaderMenu", "header_menu_ts_wizard"), Application.CompanyName, "\n\n", Application.ProductName, Application.CompanyName, "\n\n"), string.Format(software_lang.TSReadLangs("TSWizard", "tsw_title"), Application.ProductName));
                    if (ts_wizard_query == DialogResult.Yes){
                        Process.Start(new ProcessStartInfo(TS_LinkSystem.ts_wizard) { UseShellExecute = true });
                    }
                }
            }catch (Exception){ }
        }
        // BUY ME A COFFEE LINK
        // ======================================================================================================
        private void BmacToolStripMenuItem_Click(object sender, EventArgs e){
            try{
                Process.Start(new ProcessStartInfo(TS_LinkSystem.ts_bmac) { UseShellExecute = true });
            }catch (Exception){ }
        }
        // TS TOOL LAUNCHER MODULE
        // ======================================================================================================
        private void TSToolLauncher<T>(string formName, string langKey) where T : Form, new(){
            try{
                TSGetLangs software_lang = new TSGetLangs(lang_path);
                T tool = new T { Name = formName };
                if (Application.OpenForms[formName] == null){
                    tool.Show();
                }else{
                    if (Application.OpenForms[formName].WindowState == FormWindowState.Minimized){
                        Application.OpenForms[formName].WindowState = FormWindowState.Normal;
                    }
                    string public_message = string.Format(software_lang.TSReadLangs("HeaderHelp", "header_help_info_notification"), software_lang.TSReadLangs("HeaderMenu", langKey));
                    TS_MessageBoxEngine.TS_MessageBox(this, 1, public_message);
                    Application.OpenForms[formName].Activate();
                }
            }catch (Exception){ }
        }
        // ENCRYPHIX ABOUT
        // ======================================================================================================
        private void AboutToolStripMenuItem_Click(object sender, EventArgs e){
            TSToolLauncher<EncryphixAbout>("encryphix_about", "header_menu_about");
        }
        // ENCRYPHIX EXIT
        // ======================================================================================================
        private void Software_exit(){ Application.Exit(); }
        private void Encryphix_FormClosing(object sender, FormClosingEventArgs e){ Software_exit();  }
    }
}