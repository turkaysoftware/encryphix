using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace Encryphix{
    internal class TSProtection{
        private const int IterationCount = 100000;
        private const int SaltSize = 16;
        private const int BufferSize = 4 * 1024 * 1024; // 4 MB
        public const string ZipExtension = ".zip";
        public const string EncryptedExtension = ".aes";
        //
        public static Func<string, string> GetErrorMessage = key =>{
            if (Encryphix.TSProtectionErrorMessages.Messages.TryGetValue(key, out var msg)){
                return msg;
            }
            return "Unknown error.";
        };
        // ENCRYPT FOLDER
        // ======================================================================================================
        public static void EncryptFolder(string folderPath, string password, string outputDirectory = null, Action<int> reportProgress = null, bool deleteOriginal = true){
            string folderName = Path.GetFileName(folderPath.TrimEnd(Path.DirectorySeparatorChar));
            string zipPath = Path.Combine(outputDirectory ?? Path.GetDirectoryName(folderPath), folderName + ZipExtension);
            string encryptedPath = zipPath + EncryptedExtension;
            SafeDeleteFile(encryptedPath);
            try{
                ZipFile.CreateFromDirectory(folderPath, zipPath, CompressionLevel.NoCompression, false);
                EncryptFile(zipPath, encryptedPath, password, reportProgress);
                SafeDeleteFile(zipPath);
                if (deleteOriginal && Directory.Exists(folderPath)){
                    SafeDeleteDirectory(folderPath);
                }
            }catch (Exception ex){
                throw new IOException(GetErrorMessage("FolderEncryptionError"), ex);
            }
        }
        // DECRYPT FOLDER
        // ======================================================================================================
        public static void DecryptFileToFolder(string encryptedFilePath, string outputFolderPath, string password, Action<int> reportProgress = null){
            string zipPath = Path.Combine(Path.GetDirectoryName(encryptedFilePath), Path.GetFileNameWithoutExtension(encryptedFilePath));
            zipPath += ZipExtension;
            try{
                DecryptFile(encryptedFilePath, zipPath, password, reportProgress);
                ZipFile.ExtractToDirectory(zipPath, outputFolderPath);
                SafeDeleteFile(zipPath);
                SafeDeleteFile(encryptedFilePath);
            }catch (CryptographicException){
                SafeDeleteFile(zipPath);
                throw new InvalidDataException(GetErrorMessage("InvalidPasswordOrCorruptFile"));
            }catch (Exception ex){
                SafeDeleteFile(zipPath);
                throw new IOException(GetErrorMessage("FileOpenError"), ex);
            }
        }
        // ENCRYPT FILE
        // ======================================================================================================
        public static void EncryptFile(string inputFile, string outputFile, string password, Action<int> reportProgress = null, bool deleteOriginal = true){
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);
            using (FileStream fsOut = new FileStream(outputFile, FileMode.Create))
            using (Aes aes = Aes.Create()){
                fsOut.Write(salt, 0, salt.Length);
                var key = new Rfc2898DeriveBytes(password, salt, IterationCount);
                aes.Key = key.GetBytes(32);
                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                fsOut.Write(aes.IV, 0, aes.IV.Length);
                using (CryptoStream cs = new CryptoStream(fsOut, aes.CreateEncryptor(), CryptoStreamMode.Write))
                using (FileStream fsIn = new FileStream(inputFile, FileMode.Open)){
                    CopyStreamWithProgress(fsIn, cs, fsIn.Length, reportProgress);
                }
            }
            if (deleteOriginal && File.Exists(inputFile)){
                SafeDeleteFile(inputFile);
            }
        }
        // DECRYPT FILE
        // ======================================================================================================
        private static void DecryptFile(string inputFile, string outputFile, string password, Action<int> reportProgress = null){
            using (FileStream fsIn = new FileStream(inputFile, FileMode.Open))
            using (Aes aes = Aes.Create()){
                byte[] salt = new byte[SaltSize];
                if (fsIn.Read(salt, 0, salt.Length) != salt.Length){
                    throw new CryptographicException(GetErrorMessage("SaltReadError"));
                }
                var key = new Rfc2898DeriveBytes(password, salt, IterationCount);
                aes.Key = key.GetBytes(32);
                byte[] iv = new byte[aes.BlockSize / 8];
                if (fsIn.Read(iv, 0, iv.Length) != iv.Length){
                    throw new CryptographicException(GetErrorMessage("IVReadError"));
                }
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (CryptoStream cs = new CryptoStream(fsIn, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (FileStream fsOut = new FileStream(outputFile, FileMode.Create)){
                    long totalBytes = fsIn.Length - SaltSize - iv.Length;
                    CopyStreamWithProgress(cs, fsOut, totalBytes, reportProgress);
                }
            }
        }
        // DECRYPT FILE (DIRECT)
        // ======================================================================================================
        public static void DecryptFileDirect(string encryptedFilePath, string outputFilePath, string password, Action<int> reportProgress = null){
            try{
                DecryptFile(encryptedFilePath, outputFilePath, password, reportProgress);
                SafeDeleteFile(encryptedFilePath);
            }catch (CryptographicException){
                throw new InvalidDataException(GetErrorMessage("InvalidPasswordOrCorruptFile"));
            }catch (Exception ex){
                throw new IOException(GetErrorMessage("FileOpenError"), ex);
            }
        }
        // SAFE DELETE FILE
        public static void SafeDeleteFile(string path){
            try{
                if (File.Exists(path))
                    File.Delete(path);
            }catch (UnauthorizedAccessException){
                throw new UnauthorizedAccessException(GetErrorMessage("AccessError"));
            }catch (Exception ex){
                throw new IOException(GetErrorMessage("UnknownError"), ex);
            }
        }
        // SAFE DELETE DIRECTORY
        public static void SafeDeleteDirectory(string path){
            try{
                if (Directory.Exists(path))
                    Directory.Delete(path, true);
            }catch (UnauthorizedAccessException){
                throw new UnauthorizedAccessException(GetErrorMessage("AccessError"));
            }catch (Exception ex){
                throw new IOException(GetErrorMessage("UnknownError"), ex);
            }
        }
        // COPY STREAM WITH PROGRESS
        // ======================================================================================================
        private static void CopyStreamWithProgress(Stream input, Stream output, long length, Action<int> reportProgress){
            byte[] buffer = new byte[BufferSize];
            long totalRead = 0;
            int lastReportedPercent = 0;
            int bytesRead;
            while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0){
                output.Write(buffer, 0, bytesRead);
                totalRead += bytesRead;
                int percent = (int)((totalRead * 100) / length);
                if (percent > 100) percent = 100;
                if (percent != lastReportedPercent){
                    lastReportedPercent = percent;
                    reportProgress?.Invoke(percent);
                }
            }
        }
    }
}