import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/app/components/ui/card';
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer,
} from 'recharts';

const comparisonData = [
    { model: 'GraphCodeBERT', accuracy: 74.8, f1: 71.2 },
    { model: 'CodeBERT', accuracy: 66.5, f1: 62.1 },
];

export function ModelComparisonChart() {
    return (
        <Card className="bg-white/60 dark:bg-slate-900/60 backdrop-blur-xl border border-slate-200/60 dark:border-slate-700/60 shadow-sm">
            <CardHeader className="pb-2">
                <CardTitle className="text-lg font-semibold bg-gradient-to-r from-blue-600 via-cyan-500 to-purple-600 bg-clip-text text-transparent flex items-center gap-2">
                    Model Performance Comparison
                </CardTitle>
            </CardHeader>
            <CardContent>
                <div className="h-64 md:h-72">
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={comparisonData} margin={{ top: 20, right: 30, left: 20, bottom: 20 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" opacity={0.4} />
                            <XAxis dataKey="model" stroke="#64748b" tick={{ fontSize: 12 }} />
                            <YAxis domain={[0, 100]} stroke="#64748b" tick={{ fontSize: 12 }} />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                                    border: '1px solid #334155',
                                    borderRadius: '12px',
                                    color: '#e2e8f0',
                                }}
                            />
                            <Legend wrapperStyle={{ color: '#64748b', fontSize: 12 }} />
                            <Bar dataKey="accuracy" fill="#6366f1" name="Accuracy (%)" radius={[6, 6, 0, 0]} barSize={24} />
                            <Bar dataKey="f1" fill="#10b981" name="F1 Score (%)" radius={[6, 6, 0, 0]} barSize={24} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                <p className="text-sm text-center mt-4 text-slate-600 dark:text-slate-400">
                    GraphCodeBERT achieves the highest accuracy and F1-score on vulnerability detection tasks — selected as default.
                </p>
            </CardContent>
        </Card>
    );
}
