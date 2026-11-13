import React from 'react';

export interface SettingsViewProps {
  language?: string;
  onClose?: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onClose }) => {
  return (
    <div className="p-6 bg-white dark:bg-slate-900 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-800">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-slate-900 dark:text-white">Settings</h2>
        {onClose && (
          <button
            onClick={onClose}
            className="p-2 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 rounded-lg"
          >
            Close
          </button>
        )}
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400">
        Settings management view component.
      </p>
    </div>
  );
};

export default SettingsView;
