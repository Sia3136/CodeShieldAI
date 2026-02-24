# CodeShieldAI ML (GraphCodeBERT / CodeBERT)

This module contains the **Transformer Logic Layer**:
- model loading & selection (GraphCodeBERT vs CodeBERT)
- preprocessing & chunking
- inference and probability outputs
- (optional) vulnerability type classification head
- calibration/thresholding hooks

---

## Models

### GraphCodeBERT
- Strong at code semantics with structural bias from pretraining.
- Best used when you want deeper intent understanding.

### CodeBERT
- Strong general code-text semantic baseline.
- Useful for comparison and faster experimentation.

---

## ML Inference Architecture

```mermaid
flowchart TD
  A[Input code] --> B[Preprocessing<br/>normalize + chunk]
  B --> C[Tokenizer]
  C --> D[Transformer Encoder]
  D --> E[Classification Head]
  E --> F[p(vuln) + optional type logits]
  F --> G[Calibration/Threshold]
  G --> H[Aggregate: chunk→file→repo]
```

---

## Preprocessing (Recommended)
- Prefer **function-level** parsing if you have AST support.
- Fallback to **sliding windows** for large files.
- Track mapping: `chunk_id → file_path + start_line + end_line`.

**Why it matters:** remediation requires exact line ranges; analytics require correct file attribution.

---

## Outputs (Contract)
Return an ML result per chunk (then aggregated):
- `p_vuln` (0..1)
- `confidence` (can be derived from entropy/logits margin)
- `predicted_type` (optional)
- `explanations` (optional; main explanations usually composed after hybrid scoring)

---

## Training Dataset Summary
Merged dataset splits (50k samples):
- DiverseVul, Devign, ReVeal, BigVul, CrossVul, CVEfixes
- ~33k vulnerable / ~17k safe

---

## Notes on Calibration
Recommended approaches (choose one):
- temperature scaling on a validation split
- isotonic regression
- fixed thresholds tuned for high recall on critical classes

---

## Model Comparison Mode
When user selects “Compare models”:
- run inference with both models
- store side-by-side:
  - per-file risk score
  - confidence distribution
  - top findings overlap/diff
