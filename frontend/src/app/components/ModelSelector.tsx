import React from 'react';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/app/components/ui/select';

interface ModelSelectorProps {
    value: string;
    onChange: (value: string) => void;
}

export function ModelSelector({ value, onChange }: ModelSelectorProps) {
    return (
        <div className="flex items-center gap-3 bg-white/60 dark:bg-slate-900/60 backdrop-blur-md px-4 py-2.5 rounded-xl border border-slate-200/70 dark:border-slate-700/70 shadow-sm">
            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">Model:</span>
            <Select value={value} onValueChange={onChange}>
                <SelectTrigger className="w-[220px] bg-transparent border-none focus:ring-0 focus:ring-offset-0">
                    <SelectValue placeholder="Select Model" />
                </SelectTrigger>
                <SelectContent className="bg-white/95 dark:bg-slate-900/95 backdrop-blur-lg border-slate-200 dark:border-slate-700 rounded-xl">
                    <SelectItem value="GraphCodeBERT" className="text-green-600 dark:text-green-400">
                        GraphCodeBERT (Recommended)
                    </SelectItem>
                    <SelectItem value="CodeBERT">CodeBERT</SelectItem>
                </SelectContent>
            </Select>
        </div>
    );
}
