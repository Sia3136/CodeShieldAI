// Example: src/components/ScanForm.tsx  (or put in App.tsx)
import { useState } from 'react';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Loader2, Code2 } from 'lucide-react';
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
    <div className="space-y-6 p-6 max-w-4xl mx-auto">
      <div className="flex items-center gap-3">
        <Code2 className="h-8 w-8 text-primary" />
        <h1 className="text-3xl font-bold">Code Vulnerability Scanner</h1>
      </div>

      <div className="space-y-2">
        <label className="text-sm font-medium">Paste your code</label>
        <Textarea
          placeholder="def login(user_input):\n    query = 'SELECT * FROM users WHERE id = ' + user_input"
          className="font-mono min-h-[280px] text-sm leading-relaxed"
          value={code}
          onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setCode(e.target.value)}
        />
      </div>

      <Button
        onClick={handleScan}
        disabled={loading || !code.trim()}
        className="w-full sm:w-auto"
        size="lg"
      >
        {loading && <Loader2 className="mr-2 h-5 w-5 animate-spin" />}
        {loading ? 'Analyzing...' : 'Scan Code'}
      </Button>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Scan failed</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {result && (
        <div className="border rounded-lg overflow-hidden bg-card">
          <div className="p-5 border-b bg-muted/50">
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-semibold">Scan Result</h2>
              <span
                className={`px-4 py-1.5 rounded-full text-sm font-medium border ${getSeverityStyle(result.severity)}`}
              >
                {result.severity} – {result.score}%
              </span>
            </div>
          </div>

          <div className="p-5 space-y-6">
            <div>
              <h3 className="font-medium mb-1.5">Status</h3>
              <p className={`font-medium ${result.vulnerable ? 'text-red-600' : 'text-green-600'}`}>
                {result.vulnerable ? 'Vulnerable code detected' : 'No obvious vulnerabilities found'}
              </p>
            </div>

            {result.highlights && (
              <div>
                <h3 className="font-medium mb-2">Code Analysis Highlights</h3>
                <pre className="bg-muted p-4 rounded-md text-sm font-mono overflow-x-auto whitespace-pre-wrap max-h-96">
                  {result.highlights}
                </pre>
              </div>
            )}

            {result.suggested_fix && (
              <div>
                <h3 className="font-medium mb-2">💡 Recommended Fix</h3>
                <pre className="bg-green-950/40 p-4 rounded-md text-sm font-mono whitespace-pre-wrap border border-green-800/50">
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