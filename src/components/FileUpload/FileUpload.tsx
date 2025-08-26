import React, { useCallback, useState } from 'react';
import { Upload, FileText, AlertCircle, CheckCircle2 } from 'lucide-react';

interface FileUploadProps {
  onFileUpload: (file: File, content: string) => void;
  isLoading?: boolean;
  error?: string | null;
}

export const FileUpload: React.FC<FileUploadProps> = ({
  onFileUpload,
  isLoading = false,
  error = null,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    const files = e.dataTransfer.files;
    if (files && files[0]) {
      handleFile(files[0]);
    }
  }, []);

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    const files = e.target.files;
    if (files && files[0]) {
      handleFile(files[0]);
    }
  }, []);

  const handleFile = useCallback((file: File) => {
    // Validate file type
    if (file.type !== 'application/json' && !file.name.toLowerCase().endsWith('.json')) {
      return;
    }

    // Validate file size (max 50MB)
    if (file.size > 50 * 1024 * 1024) {
      return;
    }

    setUploadedFile(file);

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const content = e.target?.result as string;
        onFileUpload(file, content);
      } catch (err) {
        console.error('Error reading file:', err);
      }
    };
    reader.readAsText(file);
  }, [onFileUpload]);

  const getStatusIcon = () => {
    if (error) {
      return <AlertCircle className="w-12 h-12 text-red-500" />;
    }
    if (uploadedFile && !isLoading && !error) {
      return <CheckCircle2 className="w-12 h-12 text-green-500" />;
    }
    return <Upload className="w-12 h-12 text-gray-400" />;
  };

  const getStatusText = () => {
    if (error) {
      return "Upload failed";
    }
    if (isLoading) {
      return "Processing file...";
    }
    if (uploadedFile && !error) {
      return `Loaded: ${uploadedFile.name}`;
    }
    return "Upload Azure Firewall Policy JSON";
  };

  const getStatusSubtext = () => {
    if (error) {
      return error;
    }
    if (isLoading) {
      return "Please wait while we parse your firewall policy";
    }
    if (uploadedFile && !error) {
      return "File successfully loaded and parsed";
    }
    return "Drag and drop your JSON export file or click to browse";
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form
        className={`relative border-2 border-dashed rounded-lg p-12 text-center transition-colors ${
          dragActive
            ? 'border-blue-400 bg-blue-50'
            : error
            ? 'border-red-300 bg-red-50'
            : uploadedFile && !error
            ? 'border-green-300 bg-green-50'
            : 'border-gray-300 bg-white hover:border-gray-400'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onSubmit={(e) => e.preventDefault()}
      >
        <input
          type="file"
          accept=".json,application/json"
          onChange={handleChange}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          disabled={isLoading}
        />

        <div className="space-y-4">
          <div className="flex justify-center">
            {getStatusIcon()}
          </div>

          <div className="space-y-2">
            <p className={`text-lg font-medium ${
              error 
                ? 'text-red-700' 
                : uploadedFile && !error 
                ? 'text-green-700'
                : 'text-gray-900'
            }`}>
              {getStatusText()}
            </p>
            
            <p className={`text-sm ${
              error 
                ? 'text-red-600' 
                : uploadedFile && !error 
                ? 'text-green-600'
                : 'text-gray-500'
            }`}>
              {getStatusSubtext()}
            </p>
          </div>

          {!uploadedFile && !error && (
            <div className="space-y-3">
              <div className="flex items-center justify-center space-x-2">
                <FileText className="w-4 h-4 text-gray-400" />
                <span className="text-xs text-gray-400">JSON files only • Max 50MB</span>
              </div>
              
              <button
                type="button"
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                disabled={isLoading}
                onClick={() => {
                  const input = document.querySelector('input[type="file"]') as HTMLInputElement;
                  input?.click();
                }}
              >
                Choose File
              </button>
            </div>
          )}

          {uploadedFile && !error && (
            <button
              type="button"
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-blue-600 bg-blue-100 hover:bg-blue-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              onClick={() => {
                setUploadedFile(null);
                const input = document.querySelector('input[type="file"]') as HTMLInputElement;
                if (input) input.value = '';
              }}
            >
              Upload Different File
            </button>
          )}
        </div>
      </form>

      {/* File Requirements */}
      <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <h3 className="text-sm font-medium text-blue-900 mb-2">File Requirements:</h3>
        <ul className="text-xs text-blue-700 space-y-1">
          <li>• Export your Azure Firewall Policy as JSON from the Azure Portal</li>
          <li>• Go to your Firewall Policy → Export template → Download</li>
          <li>• Upload the template.json file (not parameters.json)</li>
          <li>• Ensure the file contains firewallPolicies and ruleCollectionGroups</li>
        </ul>
      </div>
    </div>
  );
};