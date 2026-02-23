// src/components/ScanForm.tsx
import { useState } from 'react';
import { Textarea } from '@/components/ui/textarea'; // ← assuming you have shadcn/ui Textarea
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Loader2, Code } from 'lucide-react';
import { scanCode, getSeverityStyle } from '@/lib/api';

export default function ScanForm() {
  const [code, setCode] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const data = await scanCode(code);
      setResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-10 px-4">
      <div className="flex items-center gap-3 mb-6">
        <Code className="h-8 w-8 text-primary" />
        <h1 className="text-3xl font-bold">Code Vulnerability Scanner</h1>
      </div>

      <div className="space-y-4">
        <Textarea
          placeholder="Paste your code here...&#10;e.g. query = 'SELECT * FROM users WHERE id = ' + user_input"
          className="min-h-[300px] font-mono text-sm"
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />

        <Button
          onClick={handleScan}
          disabled={loading || !code.trim()}
          className="w-full sm:w-auto"
        >
          {loading && <Loader2 className="mr-2 h-5 w-5 animate-spin" />}
          {loading ? 'Scanning...' : 'Run Scan'}
        </Button>
      </div>

      {error && (
        <Alert variant="destructive" className="mt-6">
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {result && (
        <div className="mt-8 border rounded-lg overflow-hidden bg-card">
          <div className="p-5 bg-muted/50 border-b">
            <div className="flex justify-between items-center">
              <h2 className="text-xl font-semibold">Scan Result</h2>
              <span
                className={`px-4 py-1.5 rounded-full text-sm font-medium border ${getSeverityStyle(result.severity)}`}
              >
                {result.severity} – {result.score}%
              </span>
            </div>
          </div>

          <div className="p-6 space-y-6">
            <div>
              <h3 className="font-medium mb-1">Status</h3>
              <p className={`font-semibold ${result.vulnerable ? 'text-red-600' : 'text-green-600'}`}>
                {result.vulnerable ? 'Vulnerable' : 'Appears safe'}
              </p>
            </div>

            {result.highlights && (
              <div>
                <h3 className="font-medium mb-2">Analysis Highlights</h3>
                <pre className="bg-muted p-4 rounded text-sm font-mono overflow-auto max-h-80 whitespace-pre-wrap">
                  {result.highlights}
                </pre>
              </div>
            )}

            {result.suggested_fix && (
              <div>
                <h3 className="font-medium mb-2">💡 Suggested Fix</h3>
                <pre className="bg-green-950/30 p-4 rounded text-sm font-mono whitespace-pre-wrap border border-green-800/40">
                  {result.suggested_fix}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
