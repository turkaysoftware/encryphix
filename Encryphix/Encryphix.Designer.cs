﻿namespace Encryphix
{
    partial class Encryphix
    {
        /// <summary>
        ///Gerekli tasarımcı değişkeni.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///Kullanılan tüm kaynakları temizleyin.
        /// </summary>
        ///<param name="disposing">yönetilen kaynaklar dispose edilmeliyse doğru; aksi halde yanlış.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer üretilen kod

        /// <summary>
        /// Tasarımcı desteği için gerekli metot - bu metodun 
        ///içeriğini kod düzenleyici ile değiştirmeyin.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle1 = new System.Windows.Forms.DataGridViewCellStyle();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle2 = new System.Windows.Forms.DataGridViewCellStyle();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle3 = new System.Windows.Forms.DataGridViewCellStyle();
            System.Windows.Forms.DataGridViewCellStyle dataGridViewCellStyle4 = new System.Windows.Forms.DataGridViewCellStyle();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Encryphix));
            this.PanelBack = new System.Windows.Forms.Panel();
            this.DragAndDropLabel = new System.Windows.Forms.Label();
            this.Progress_BG = new System.Windows.Forms.Panel();
            this.Progress_FE = new System.Windows.Forms.Panel();
            this.PanelControl = new System.Windows.Forms.Panel();
            this.CheckOrjFileDelete = new System.Windows.Forms.CheckBox();
            this.PanelBtns = new System.Windows.Forms.Panel();
            this.BtnSelect = new System.Windows.Forms.Button();
            this.BtnBurner = new System.Windows.Forms.Button();
            this.BtnSavePath = new System.Windows.Forms.Button();
            this.BtnShowPassword = new System.Windows.Forms.Button();
            this.TextBox_SaveFolder = new System.Windows.Forms.TextBox();
            this.Label_SaveFolder = new System.Windows.Forms.Label();
            this.TextBox_Password = new System.Windows.Forms.TextBox();
            this.Label_Password = new System.Windows.Forms.Label();
            this.FAF_DGV = new System.Windows.Forms.DataGridView();
            this.HeaderMenu = new System.Windows.Forms.MenuStrip();
            this.settingsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.themeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.lightThemeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.darkThemeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.languageToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.englishToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.turkishToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.startupToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.windowedToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.fullScreenToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.checkForUpdateToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.tSWizardToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.bmacToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.aboutToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.MainToolTip = new System.Windows.Forms.ToolTip(this.components);
            this.PanelBack.SuspendLayout();
            this.Progress_BG.SuspendLayout();
            this.PanelControl.SuspendLayout();
            this.PanelBtns.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.FAF_DGV)).BeginInit();
            this.HeaderMenu.SuspendLayout();
            this.SuspendLayout();
            // 
            // PanelBack
            // 
            this.PanelBack.Controls.Add(this.DragAndDropLabel);
            this.PanelBack.Controls.Add(this.Progress_BG);
            this.PanelBack.Controls.Add(this.PanelControl);
            this.PanelBack.Controls.Add(this.FAF_DGV);
            this.PanelBack.Dock = System.Windows.Forms.DockStyle.Fill;
            this.PanelBack.Location = new System.Drawing.Point(0, 24);
            this.PanelBack.Name = "PanelBack";
            this.PanelBack.Padding = new System.Windows.Forms.Padding(15);
            this.PanelBack.Size = new System.Drawing.Size(1008, 577);
            this.PanelBack.TabIndex = 1;
            // 
            // DragAndDropLabel
            // 
            this.DragAndDropLabel.Anchor = System.Windows.Forms.AnchorStyles.None;
            this.DragAndDropLabel.BackColor = System.Drawing.Color.Transparent;
            this.DragAndDropLabel.Font = new System.Drawing.Font("Segoe UI Semibold", 11F, System.Drawing.FontStyle.Bold);
            this.DragAndDropLabel.ForeColor = System.Drawing.Color.Black;
            this.DragAndDropLabel.Location = new System.Drawing.Point(279, 179);
            this.DragAndDropLabel.Margin = new System.Windows.Forms.Padding(3, 0, 3, 5);
            this.DragAndDropLabel.Name = "DragAndDropLabel";
            this.DragAndDropLabel.Size = new System.Drawing.Size(450, 45);
            this.DragAndDropLabel.TabIndex = 1;
            this.DragAndDropLabel.Text = "ÖĞE SÜRÜKLEYİN";
            this.DragAndDropLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // Progress_BG
            // 
            this.Progress_BG.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.Progress_BG.BackColor = System.Drawing.Color.White;
            this.Progress_BG.Controls.Add(this.Progress_FE);
            this.Progress_BG.Location = new System.Drawing.Point(15, 400);
            this.Progress_BG.Name = "Progress_BG";
            this.Progress_BG.Size = new System.Drawing.Size(978, 5);
            this.Progress_BG.TabIndex = 2;
            this.Progress_BG.Visible = false;
            // 
            // Progress_FE
            // 
            this.Progress_FE.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(90)))), ((int)(((byte)(111)))), ((int)(((byte)(141)))));
            this.Progress_FE.Dock = System.Windows.Forms.DockStyle.Left;
            this.Progress_FE.Location = new System.Drawing.Point(0, 0);
            this.Progress_FE.Name = "Progress_FE";
            this.Progress_FE.Size = new System.Drawing.Size(99, 5);
            this.Progress_FE.TabIndex = 0;
            // 
            // PanelControl
            // 
            this.PanelControl.BackColor = System.Drawing.Color.White;
            this.PanelControl.Controls.Add(this.CheckOrjFileDelete);
            this.PanelControl.Controls.Add(this.PanelBtns);
            this.PanelControl.Controls.Add(this.BtnSavePath);
            this.PanelControl.Controls.Add(this.BtnShowPassword);
            this.PanelControl.Controls.Add(this.TextBox_SaveFolder);
            this.PanelControl.Controls.Add(this.Label_SaveFolder);
            this.PanelControl.Controls.Add(this.TextBox_Password);
            this.PanelControl.Controls.Add(this.Label_Password);
            this.PanelControl.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.PanelControl.Location = new System.Drawing.Point(15, 418);
            this.PanelControl.Margin = new System.Windows.Forms.Padding(3, 10, 3, 3);
            this.PanelControl.Name = "PanelControl";
            this.PanelControl.Padding = new System.Windows.Forms.Padding(10);
            this.PanelControl.Size = new System.Drawing.Size(978, 144);
            this.PanelControl.TabIndex = 3;
            // 
            // CheckOrjFileDelete
            // 
            this.CheckOrjFileDelete.CheckAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.CheckOrjFileDelete.Cursor = System.Windows.Forms.Cursors.Hand;
            this.CheckOrjFileDelete.Font = new System.Drawing.Font("Segoe UI Semibold", 9.75F, System.Drawing.FontStyle.Bold);
            this.CheckOrjFileDelete.Location = new System.Drawing.Point(195, 80);
            this.CheckOrjFileDelete.Name = "CheckOrjFileDelete";
            this.CheckOrjFileDelete.Size = new System.Drawing.Size(142, 21);
            this.CheckOrjFileDelete.TabIndex = 4;
            this.CheckOrjFileDelete.Text = "Orijinali Sil";
            this.CheckOrjFileDelete.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.CheckOrjFileDelete.UseVisualStyleBackColor = true;
            // 
            // PanelBtns
            // 
            this.PanelBtns.Controls.Add(this.BtnSelect);
            this.PanelBtns.Controls.Add(this.BtnBurner);
            this.PanelBtns.Dock = System.Windows.Forms.DockStyle.Right;
            this.PanelBtns.Location = new System.Drawing.Point(743, 10);
            this.PanelBtns.Name = "PanelBtns";
            this.PanelBtns.Padding = new System.Windows.Forms.Padding(0, 12, 0, 12);
            this.PanelBtns.Size = new System.Drawing.Size(225, 124);
            this.PanelBtns.TabIndex = 7;
            // 
            // BtnSelect
            // 
            this.BtnSelect.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(90)))), ((int)(((byte)(111)))), ((int)(((byte)(141)))));
            this.BtnSelect.Cursor = System.Windows.Forms.Cursors.Hand;
            this.BtnSelect.Dock = System.Windows.Forms.DockStyle.Top;
            this.BtnSelect.FlatAppearance.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(86)))), ((int)(((byte)(106)))), ((int)(((byte)(137)))));
            this.BtnSelect.FlatAppearance.BorderSize = 0;
            this.BtnSelect.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.BtnSelect.Font = new System.Drawing.Font("Segoe UI Semibold", 10F, System.Drawing.FontStyle.Bold);
            this.BtnSelect.ForeColor = System.Drawing.Color.White;
            this.BtnSelect.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.BtnSelect.Location = new System.Drawing.Point(0, 12);
            this.BtnSelect.Margin = new System.Windows.Forms.Padding(0, 10, 0, 0);
            this.BtnSelect.Name = "BtnSelect";
            this.BtnSelect.Padding = new System.Windows.Forms.Padding(5, 0, 5, 0);
            this.BtnSelect.Size = new System.Drawing.Size(225, 45);
            this.BtnSelect.TabIndex = 0;
            this.BtnSelect.Text = " ÖĞE SEÇ";
            this.BtnSelect.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.BtnSelect.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageBeforeText;
            this.BtnSelect.UseVisualStyleBackColor = false;
            this.BtnSelect.Click += new System.EventHandler(this.BtnSelect_Click);
            // 
            // BtnBurner
            // 
            this.BtnBurner.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(90)))), ((int)(((byte)(111)))), ((int)(((byte)(141)))));
            this.BtnBurner.Cursor = System.Windows.Forms.Cursors.Hand;
            this.BtnBurner.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.BtnBurner.FlatAppearance.BorderColor = System.Drawing.Color.FromArgb(((int)(((byte)(86)))), ((int)(((byte)(106)))), ((int)(((byte)(137)))));
            this.BtnBurner.FlatAppearance.BorderSize = 0;
            this.BtnBurner.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.BtnBurner.Font = new System.Drawing.Font("Segoe UI Semibold", 10F, System.Drawing.FontStyle.Bold);
            this.BtnBurner.ForeColor = System.Drawing.Color.White;
            this.BtnBurner.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.BtnBurner.Location = new System.Drawing.Point(0, 67);
            this.BtnBurner.Margin = new System.Windows.Forms.Padding(0, 0, 0, 10);
            this.BtnBurner.Name = "BtnBurner";
            this.BtnBurner.Padding = new System.Windows.Forms.Padding(5, 0, 5, 0);
            this.BtnBurner.Size = new System.Drawing.Size(225, 45);
            this.BtnBurner.TabIndex = 1;
            this.BtnBurner.Text = " ŞİFRELE";
            this.BtnBurner.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.BtnBurner.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageBeforeText;
            this.BtnBurner.UseVisualStyleBackColor = false;
            this.BtnBurner.Click += new System.EventHandler(this.BtnBurner_Click);
            // 
            // BtnSavePath
            // 
            this.BtnSavePath.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(90)))), ((int)(((byte)(111)))), ((int)(((byte)(141)))));
            this.BtnSavePath.Cursor = System.Windows.Forms.Cursors.Hand;
            this.BtnSavePath.FlatAppearance.BorderSize = 0;
            this.BtnSavePath.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.BtnSavePath.Font = new System.Drawing.Font("Segoe UI Semibold", 10.5F, System.Drawing.FontStyle.Bold);
            this.BtnSavePath.Location = new System.Drawing.Point(312, 106);
            this.BtnSavePath.Margin = new System.Windows.Forms.Padding(3, 3, 12, 3);
            this.BtnSavePath.Name = "BtnSavePath";
            this.BtnSavePath.Size = new System.Drawing.Size(25, 25);
            this.BtnSavePath.TabIndex = 6;
            this.BtnSavePath.UseVisualStyleBackColor = false;
            this.BtnSavePath.Click += new System.EventHandler(this.BtnSavePath_Click);
            // 
            // BtnShowPassword
            // 
            this.BtnShowPassword.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(90)))), ((int)(((byte)(111)))), ((int)(((byte)(141)))));
            this.BtnShowPassword.Cursor = System.Windows.Forms.Cursors.Hand;
            this.BtnShowPassword.FlatAppearance.BorderSize = 0;
            this.BtnShowPassword.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.BtnShowPassword.Font = new System.Drawing.Font("Segoe UI Semibold", 10.5F, System.Drawing.FontStyle.Bold);
            this.BtnShowPassword.Location = new System.Drawing.Point(312, 38);
            this.BtnShowPassword.Margin = new System.Windows.Forms.Padding(3, 3, 12, 3);
            this.BtnShowPassword.Name = "BtnShowPassword";
            this.BtnShowPassword.Size = new System.Drawing.Size(25, 25);
            this.BtnShowPassword.TabIndex = 5;
            this.BtnShowPassword.UseVisualStyleBackColor = false;
            this.BtnShowPassword.Click += new System.EventHandler(this.BtnShowPassword_Click);
            // 
            // TextBox_SaveFolder
            // 
            this.TextBox_SaveFolder.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.TextBox_SaveFolder.BackColor = System.Drawing.Color.White;
            this.TextBox_SaveFolder.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.TextBox_SaveFolder.Font = new System.Drawing.Font("Segoe UI Semibold", 9.75F, System.Drawing.FontStyle.Bold);
            this.TextBox_SaveFolder.ForeColor = System.Drawing.Color.Black;
            this.TextBox_SaveFolder.Location = new System.Drawing.Point(13, 106);
            this.TextBox_SaveFolder.Name = "TextBox_SaveFolder";
            this.TextBox_SaveFolder.Size = new System.Drawing.Size(300, 25);
            this.TextBox_SaveFolder.TabIndex = 3;
            // 
            // Label_SaveFolder
            // 
            this.Label_SaveFolder.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.Label_SaveFolder.AutoSize = true;
            this.Label_SaveFolder.Font = new System.Drawing.Font("Segoe UI Semibold", 10F, System.Drawing.FontStyle.Bold);
            this.Label_SaveFolder.ForeColor = System.Drawing.Color.Black;
            this.Label_SaveFolder.Location = new System.Drawing.Point(9, 81);
            this.Label_SaveFolder.Margin = new System.Windows.Forms.Padding(3);
            this.Label_SaveFolder.Name = "Label_SaveFolder";
            this.Label_SaveFolder.Size = new System.Drawing.Size(143, 19);
            this.Label_SaveFolder.TabIndex = 2;
            this.Label_SaveFolder.Text = "Kaydedilecek Konum:";
            // 
            // TextBox_Password
            // 
            this.TextBox_Password.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.TextBox_Password.BackColor = System.Drawing.Color.White;
            this.TextBox_Password.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.TextBox_Password.Font = new System.Drawing.Font("Segoe UI Semibold", 9.75F, System.Drawing.FontStyle.Bold);
            this.TextBox_Password.ForeColor = System.Drawing.Color.Black;
            this.TextBox_Password.Location = new System.Drawing.Point(13, 38);
            this.TextBox_Password.Margin = new System.Windows.Forms.Padding(3, 3, 3, 15);
            this.TextBox_Password.Name = "TextBox_Password";
            this.TextBox_Password.Size = new System.Drawing.Size(300, 25);
            this.TextBox_Password.TabIndex = 1;
            this.TextBox_Password.UseSystemPasswordChar = true;
            // 
            // Label_Password
            // 
            this.Label_Password.AutoSize = true;
            this.Label_Password.Font = new System.Drawing.Font("Segoe UI Semibold", 10F, System.Drawing.FontStyle.Bold);
            this.Label_Password.ForeColor = System.Drawing.Color.Black;
            this.Label_Password.Location = new System.Drawing.Point(9, 13);
            this.Label_Password.Margin = new System.Windows.Forms.Padding(3);
            this.Label_Password.Name = "Label_Password";
            this.Label_Password.Size = new System.Drawing.Size(41, 19);
            this.Label_Password.TabIndex = 0;
            this.Label_Password.Text = "Şifre:";
            // 
            // FAF_DGV
            // 
            this.FAF_DGV.AllowUserToAddRows = false;
            this.FAF_DGV.AllowUserToDeleteRows = false;
            this.FAF_DGV.AllowUserToResizeRows = false;
            dataGridViewCellStyle1.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(237)))), ((int)(((byte)(237)))), ((int)(((byte)(237)))));
            this.FAF_DGV.AlternatingRowsDefaultCellStyle = dataGridViewCellStyle1;
            this.FAF_DGV.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.FAF_DGV.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.FAF_DGV.BackgroundColor = System.Drawing.Color.White;
            this.FAF_DGV.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.FAF_DGV.ColumnHeadersBorderStyle = System.Windows.Forms.DataGridViewHeaderBorderStyle.Single;
            dataGridViewCellStyle2.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle2.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(88)))), ((int)(((byte)(45)))), ((int)(((byte)(163)))));
            dataGridViewCellStyle2.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F);
            dataGridViewCellStyle2.ForeColor = System.Drawing.Color.White;
            dataGridViewCellStyle2.Padding = new System.Windows.Forms.Padding(0, 3, 0, 3);
            dataGridViewCellStyle2.SelectionBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(88)))), ((int)(((byte)(45)))), ((int)(((byte)(163)))));
            dataGridViewCellStyle2.SelectionForeColor = System.Drawing.Color.White;
            dataGridViewCellStyle2.WrapMode = System.Windows.Forms.DataGridViewTriState.True;
            this.FAF_DGV.ColumnHeadersDefaultCellStyle = dataGridViewCellStyle2;
            this.FAF_DGV.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.FAF_DGV.Cursor = System.Windows.Forms.Cursors.Hand;
            dataGridViewCellStyle3.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle3.BackColor = System.Drawing.Color.White;
            dataGridViewCellStyle3.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            dataGridViewCellStyle3.ForeColor = System.Drawing.SystemColors.ControlText;
            dataGridViewCellStyle3.SelectionBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(88)))), ((int)(((byte)(45)))), ((int)(((byte)(163)))));
            dataGridViewCellStyle3.SelectionForeColor = System.Drawing.Color.White;
            dataGridViewCellStyle3.WrapMode = System.Windows.Forms.DataGridViewTriState.False;
            this.FAF_DGV.DefaultCellStyle = dataGridViewCellStyle3;
            this.FAF_DGV.EnableHeadersVisualStyles = false;
            this.FAF_DGV.GridColor = System.Drawing.Color.Gray;
            this.FAF_DGV.Location = new System.Drawing.Point(15, 15);
            this.FAF_DGV.Margin = new System.Windows.Forms.Padding(3, 3, 3, 10);
            this.FAF_DGV.MultiSelect = false;
            this.FAF_DGV.Name = "FAF_DGV";
            this.FAF_DGV.ReadOnly = true;
            dataGridViewCellStyle4.Alignment = System.Windows.Forms.DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle4.BackColor = System.Drawing.SystemColors.Control;
            dataGridViewCellStyle4.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            dataGridViewCellStyle4.ForeColor = System.Drawing.SystemColors.WindowText;
            dataGridViewCellStyle4.SelectionBackColor = System.Drawing.Color.FromArgb(((int)(((byte)(88)))), ((int)(((byte)(45)))), ((int)(((byte)(163)))));
            dataGridViewCellStyle4.SelectionForeColor = System.Drawing.SystemColors.HighlightText;
            dataGridViewCellStyle4.WrapMode = System.Windows.Forms.DataGridViewTriState.True;
            this.FAF_DGV.RowHeadersDefaultCellStyle = dataGridViewCellStyle4;
            this.FAF_DGV.RowHeadersVisible = false;
            this.FAF_DGV.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.FAF_DGV.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.FAF_DGV.Size = new System.Drawing.Size(978, 372);
            this.FAF_DGV.TabIndex = 0;
            // 
            // HeaderMenu
            // 
            this.HeaderMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.settingsToolStripMenuItem,
            this.tSWizardToolStripMenuItem,
            this.bmacToolStripMenuItem,
            this.aboutToolStripMenuItem});
            this.HeaderMenu.Location = new System.Drawing.Point(0, 0);
            this.HeaderMenu.Name = "HeaderMenu";
            this.HeaderMenu.Size = new System.Drawing.Size(1008, 24);
            this.HeaderMenu.TabIndex = 0;
            this.HeaderMenu.Text = "menuStrip1";
            // 
            // settingsToolStripMenuItem
            // 
            this.settingsToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.themeToolStripMenuItem,
            this.languageToolStripMenuItem,
            this.startupToolStripMenuItem,
            this.checkForUpdateToolStripMenuItem});
            this.settingsToolStripMenuItem.Name = "settingsToolStripMenuItem";
            this.settingsToolStripMenuItem.Size = new System.Drawing.Size(61, 20);
            this.settingsToolStripMenuItem.Text = "Settings";
            // 
            // themeToolStripMenuItem
            // 
            this.themeToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.lightThemeToolStripMenuItem,
            this.darkThemeToolStripMenuItem});
            this.themeToolStripMenuItem.Name = "themeToolStripMenuItem";
            this.themeToolStripMenuItem.Size = new System.Drawing.Size(196, 22);
            this.themeToolStripMenuItem.Text = "Theme";
            // 
            // lightThemeToolStripMenuItem
            // 
            this.lightThemeToolStripMenuItem.Name = "lightThemeToolStripMenuItem";
            this.lightThemeToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F1;
            this.lightThemeToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.lightThemeToolStripMenuItem.Text = "Light Theme";
            this.lightThemeToolStripMenuItem.Click += new System.EventHandler(this.LightThemeToolStripMenuItem_Click);
            // 
            // darkThemeToolStripMenuItem
            // 
            this.darkThemeToolStripMenuItem.Name = "darkThemeToolStripMenuItem";
            this.darkThemeToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F2;
            this.darkThemeToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.darkThemeToolStripMenuItem.Text = "Dark Theme";
            this.darkThemeToolStripMenuItem.Click += new System.EventHandler(this.DarkThemeToolStripMenuItem_Click);
            // 
            // languageToolStripMenuItem
            // 
            this.languageToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.englishToolStripMenuItem,
            this.turkishToolStripMenuItem});
            this.languageToolStripMenuItem.Name = "languageToolStripMenuItem";
            this.languageToolStripMenuItem.Size = new System.Drawing.Size(196, 22);
            this.languageToolStripMenuItem.Text = "Language";
            // 
            // englishToolStripMenuItem
            // 
            this.englishToolStripMenuItem.Name = "englishToolStripMenuItem";
            this.englishToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.englishToolStripMenuItem.Text = "English";
            this.englishToolStripMenuItem.Click += new System.EventHandler(this.EnglishToolStripMenuItem_Click);
            // 
            // turkishToolStripMenuItem
            // 
            this.turkishToolStripMenuItem.Name = "turkishToolStripMenuItem";
            this.turkishToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.turkishToolStripMenuItem.Text = "Turkish";
            this.turkishToolStripMenuItem.Click += new System.EventHandler(this.TurkishToolStripMenuItem_Click);
            // 
            // startupToolStripMenuItem
            // 
            this.startupToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.windowedToolStripMenuItem,
            this.fullScreenToolStripMenuItem});
            this.startupToolStripMenuItem.Name = "startupToolStripMenuItem";
            this.startupToolStripMenuItem.Size = new System.Drawing.Size(196, 22);
            this.startupToolStripMenuItem.Text = "Startup Mode";
            // 
            // windowedToolStripMenuItem
            // 
            this.windowedToolStripMenuItem.Name = "windowedToolStripMenuItem";
            this.windowedToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F3;
            this.windowedToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.windowedToolStripMenuItem.Text = "Windowed";
            this.windowedToolStripMenuItem.Click += new System.EventHandler(this.WindowedToolStripMenuItem_Click);
            // 
            // fullScreenToolStripMenuItem
            // 
            this.fullScreenToolStripMenuItem.Name = "fullScreenToolStripMenuItem";
            this.fullScreenToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F4;
            this.fullScreenToolStripMenuItem.Size = new System.Drawing.Size(180, 22);
            this.fullScreenToolStripMenuItem.Text = "Full Screen";
            this.fullScreenToolStripMenuItem.Click += new System.EventHandler(this.FullScreenToolStripMenuItem_Click);
            // 
            // checkForUpdateToolStripMenuItem
            // 
            this.checkForUpdateToolStripMenuItem.Name = "checkForUpdateToolStripMenuItem";
            this.checkForUpdateToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F11;
            this.checkForUpdateToolStripMenuItem.Size = new System.Drawing.Size(196, 22);
            this.checkForUpdateToolStripMenuItem.Text = "Check for Updates";
            this.checkForUpdateToolStripMenuItem.Click += new System.EventHandler(this.CheckForUpdateToolStripMenuItem_Click);
            // 
            // tSWizardToolStripMenuItem
            // 
            this.tSWizardToolStripMenuItem.Name = "tSWizardToolStripMenuItem";
            this.tSWizardToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)(((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.Shift) 
            | System.Windows.Forms.Keys.S)));
            this.tSWizardToolStripMenuItem.Size = new System.Drawing.Size(68, 20);
            this.tSWizardToolStripMenuItem.Text = "TSWizard";
            this.tSWizardToolStripMenuItem.Click += new System.EventHandler(this.TSWizardToolStripMenuItem_Click);
            // 
            // bmacToolStripMenuItem
            // 
            this.bmacToolStripMenuItem.Name = "bmacToolStripMenuItem";
            this.bmacToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)(((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.Shift) 
            | System.Windows.Forms.Keys.D)));
            this.bmacToolStripMenuItem.Size = new System.Drawing.Size(49, 20);
            this.bmacToolStripMenuItem.Text = "Bmac";
            this.bmacToolStripMenuItem.Click += new System.EventHandler(this.BmacToolStripMenuItem_Click);
            // 
            // aboutToolStripMenuItem
            // 
            this.aboutToolStripMenuItem.Name = "aboutToolStripMenuItem";
            this.aboutToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F12;
            this.aboutToolStripMenuItem.Size = new System.Drawing.Size(52, 20);
            this.aboutToolStripMenuItem.Text = "About";
            this.aboutToolStripMenuItem.Click += new System.EventHandler(this.AboutToolStripMenuItem_Click);
            // 
            // MainToolTip
            // 
            this.MainToolTip.OwnerDraw = true;
            this.MainToolTip.Draw += new System.Windows.Forms.DrawToolTipEventHandler(this.MainToolTip_Draw);
            // 
            // Encryphix
            // 
            this.AllowDrop = true;
            this.AutoScaleDimensions = new System.Drawing.SizeF(96F, 96F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Dpi;
            this.ClientSize = new System.Drawing.Size(1008, 601);
            this.Controls.Add(this.PanelBack);
            this.Controls.Add(this.HeaderMenu);
            this.DoubleBuffered = true;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MinimumSize = new System.Drawing.Size(1024, 640);
            this.Name = "Encryphix";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Encryphix";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.Encryphix_FormClosing);
            this.Load += new System.EventHandler(this.Encryphix_Load);
            this.DragDrop += new System.Windows.Forms.DragEventHandler(this.Encryphix_DragDrop);
            this.DragEnter += new System.Windows.Forms.DragEventHandler(this.Encryphix_DragEnter);
            this.PanelBack.ResumeLayout(false);
            this.Progress_BG.ResumeLayout(false);
            this.PanelControl.ResumeLayout(false);
            this.PanelControl.PerformLayout();
            this.PanelBtns.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.FAF_DGV)).EndInit();
            this.HeaderMenu.ResumeLayout(false);
            this.HeaderMenu.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Panel PanelBack;
        private System.Windows.Forms.Panel PanelControl;
        private System.Windows.Forms.Button BtnBurner;
        private System.Windows.Forms.Label Label_Password;
        private System.Windows.Forms.TextBox TextBox_Password;
        private System.Windows.Forms.Panel Progress_BG;
        private System.Windows.Forms.Panel Progress_FE;
        private System.Windows.Forms.Label DragAndDropLabel;
        private System.Windows.Forms.Button BtnSelect;
        private System.Windows.Forms.TextBox TextBox_SaveFolder;
        private System.Windows.Forms.Label Label_SaveFolder;
        private System.Windows.Forms.Button BtnShowPassword;
        private System.Windows.Forms.Button BtnSavePath;
        private System.Windows.Forms.Panel PanelBtns;
        private System.Windows.Forms.MenuStrip HeaderMenu;
        private System.Windows.Forms.ToolStripMenuItem settingsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem themeToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem lightThemeToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem darkThemeToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem languageToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem englishToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem turkishToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem startupToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem checkForUpdateToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem tSWizardToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem bmacToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem windowedToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem fullScreenToolStripMenuItem;
        private System.Windows.Forms.DataGridView FAF_DGV;
        private System.Windows.Forms.CheckBox CheckOrjFileDelete;
        private System.Windows.Forms.ToolTip MainToolTip;
    }
}

