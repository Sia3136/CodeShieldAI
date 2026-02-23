import jsPDF from 'jspdf';

interface Vulnerability {
    id: string;
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    line: number;
    description: string;
    recommendation: string;
    fix?: string;
    codeSnippet?: string;
    confidence: number;
}

interface ScanResult {
    riskScore: number;
    vulnerabilities: Vulnerability[];
    linesScanned: number;
    timeElapsed: number;
}

export const generatePDFReport = (
    scanResult: ScanResult,
    code: string,
    model: string
) => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 20;
    const maxWidth = pageWidth - 2 * margin;
    let yPosition = 20;

    // Helper function to add new page if needed
    const checkPageBreak = (requiredSpace: number) => {
        if (yPosition + requiredSpace > pageHeight - margin) {
            doc.addPage();
            yPosition = 20;
            return true;
        }
        return false;
    };

    // Helper function to wrap text
    const addWrappedText = (text: string, x: number, fontSize: number, maxWidth: number, isBold = false) => {
        doc.setFontSize(fontSize);
        doc.setFont('helvetica', isBold ? 'bold' : 'normal');
        const lines = doc.splitTextToSize(text, maxWidth);
        lines.forEach((line: string) => {
            checkPageBreak(fontSize / 2);
            doc.text(line, x, yPosition);
            yPosition += fontSize / 2;
        });
    };

    // Header
    doc.setFillColor(59, 130, 246); // Blue
    doc.rect(0, 0, pageWidth, 40, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('CodeShieldAI', margin, 25);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'normal');
    doc.text('Security Vulnerability Report', margin, 33);

    yPosition = 50;

    // Metadata Section
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    const scanDate = new Date().toLocaleString();
    doc.text(`Scan Date: ${scanDate}`, margin, yPosition);
    yPosition += 6;
    doc.text(`Model Used: ${model}`, margin, yPosition);
    yPosition += 6;
    doc.text(`Lines Scanned: ${scanResult.linesScanned}`, margin, yPosition);
    yPosition += 6;
    doc.text(`Scan Duration: ${scanResult.timeElapsed.toFixed(2)}s`, margin, yPosition);
    yPosition += 12;

    // Risk Score Section
    checkPageBreak(30);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Risk Assessment', margin, yPosition);
    yPosition += 8;

    // Risk score box
    const riskLevel = scanResult.riskScore >= 70 ? 'Critical' :
        scanResult.riskScore >= 50 ? 'High' :
            scanResult.riskScore >= 30 ? 'Medium' : 'Low';

    const riskColor = scanResult.riskScore >= 70 ? [239, 68, 68] :
        scanResult.riskScore >= 50 ? [249, 115, 22] :
            scanResult.riskScore >= 30 ? [234, 179, 8] : [59, 130, 246];

    doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
    doc.roundedRect(margin, yPosition, 60, 20, 3, 3, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text(`${scanResult.riskScore}`, margin + 30, yPosition + 10, { align: 'center' });
    doc.setFontSize(10);
    doc.text(riskLevel, margin + 30, yPosition + 16, { align: 'center' });

    doc.setTextColor(0, 0, 0);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(`Total Vulnerabilities: ${scanResult.vulnerabilities.length}`, margin + 70, yPosition + 10);
    const criticalHigh = scanResult.vulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'high').length;
    doc.text(`Critical/High: ${criticalHigh}`, margin + 70, yPosition + 16);

    yPosition += 30;

    // Vulnerabilities Section
    if (scanResult.vulnerabilities.length > 0) {
        checkPageBreak(20);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text('Detected Vulnerabilities', margin, yPosition);
        yPosition += 10;

        scanResult.vulnerabilities.forEach((vuln, index) => {
            checkPageBreak(50);

            // Vulnerability header
            doc.setFillColor(240, 240, 240);
            doc.roundedRect(margin, yPosition, maxWidth, 8, 2, 2, 'F');

            // Severity badge
            const sevColor = vuln.severity === 'critical' ? [239, 68, 68] :
                vuln.severity === 'high' ? [249, 115, 22] :
                    vuln.severity === 'medium' ? [234, 179, 8] : [59, 130, 246];

            doc.setFillColor(sevColor[0], sevColor[1], sevColor[2]);
            doc.roundedRect(margin + 2, yPosition + 1, 20, 6, 1, 1, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(8);
            doc.setFont('helvetica', 'bold');
            doc.text(vuln.severity.toUpperCase(), margin + 12, yPosition + 5, { align: 'center' });

            // Vulnerability type
            doc.setTextColor(0, 0, 0);
            doc.setFontSize(10);
            doc.setFont('helvetica', 'bold');
            doc.text(`${vuln.type} (Line ${vuln.line})`, margin + 25, yPosition + 5);

            yPosition += 10;

            // Description
            doc.setFontSize(9);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(60, 60, 60);
            addWrappedText(vuln.description, margin + 2, 9, maxWidth - 4);
            yPosition += 2;

            // Code snippet
            if (vuln.codeSnippet) {
                checkPageBreak(15);
                doc.setFillColor(250, 250, 250);
                const snippetHeight = Math.min(doc.splitTextToSize(vuln.codeSnippet, maxWidth - 8).length * 4 + 4, 20);
                doc.roundedRect(margin + 2, yPosition, maxWidth - 4, snippetHeight, 1, 1, 'F');
                doc.setFontSize(8);
                doc.setFont('courier', 'normal');
                doc.setTextColor(0, 0, 0);
                const snippetLines = doc.splitTextToSize(vuln.codeSnippet, maxWidth - 8);
                snippetLines.slice(0, 4).forEach((line: string, i: number) => {
                    doc.text(line, margin + 4, yPosition + 4 + i * 4);
                });
                yPosition += snippetHeight + 2;
            }

            // Fix/Recommendation
            checkPageBreak(20);
            doc.setFillColor(219, 234, 254); // Light blue
            doc.roundedRect(margin + 2, yPosition, maxWidth - 4, 6, 1, 1, 'F');
            doc.setFontSize(8);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(30, 64, 175);
            doc.text('Recommendation:', margin + 4, yPosition + 4);
            yPosition += 8;

            doc.setFont('helvetica', 'normal');
            doc.setTextColor(60, 60, 60);
            doc.setFontSize(8);
            const fixText = vuln.fix || vuln.recommendation;
            addWrappedText(fixText, margin + 4, 8, maxWidth - 8);
            yPosition += 8;
        });
    } else {
        checkPageBreak(20);
        doc.setFillColor(220, 252, 231); // Light green
        doc.roundedRect(margin, yPosition, maxWidth, 15, 3, 3, 'F');
        doc.setTextColor(22, 101, 52);
        doc.setFontSize(12);
        doc.setFont('helvetica', 'bold');
        doc.text('✓ No vulnerabilities detected!', margin + maxWidth / 2, yPosition + 10, { align: 'center' });
        yPosition += 20;
    }

    // Footer
    const totalPages = doc.internal.pages.length - 1;
    for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(150, 150, 150);
        doc.setFont('helvetica', 'normal');
        doc.text(
            `Page ${i} of ${totalPages} | Generated by CodeShieldAI`,
            pageWidth / 2,
            pageHeight - 10,
            { align: 'center' }
        );
    }

    // Save the PDF
    const filename = `CodeShieldAI_Report_${new Date().getTime()}.pdf`;
    doc.save(filename);
};
