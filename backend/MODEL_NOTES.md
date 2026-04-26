# Model issue: what to do next

The current weak point is not only the local model. It is the combination of:

1. long, noisy article text
2. a large system prompt
3. one-shot JSON extraction from a small local model
4. deterministic extraction running too late instead of first

## Recommended pipeline

Use this order:

1. **Fetch + clean article text**
2. **Run deterministic IOC extraction first**
3. **Send only the cleaned, relevant article text to the model**
4. **Ask the model only for:**
   - title
   - 2-3 sentence summary
   - attack stages
   - behaviors with evidence
5. **Merge model output with deterministic artifacts**
6. **Compile S1 hunts deterministically**

## Immediate fixes

### 1. Shrink the article window
Use 4k-6k chars, not 12k.

### 2. Remove S1 query teaching from article-analysis prompt
The model should interpret the article, not write the final S1 syntax.

### 3. Make the model return a tiny schema
Good schema:

```json
{
  "title": "",
  "summary": "",
  "attack_stages": [],
  "behaviors": [
    {
      "type": "",
      "confidence": "",
      "rationale": "",
      "hunt_priority": 1,
      "evidence": {}
    }
  ]
}
```

### 4. Fail loudly when the model is sparse
If title+summary+behaviors are empty, attach a warning and rely on deterministic fallback.

## If hardware is the constraint

If the laptop is too slow, do one of these instead of making prompts bigger:

- reduce prompt size
- reduce output token budget
- do two smaller model calls instead of one big one
- move article analysis to a stronger model and keep query compilation deterministic

## Best role for the model

The model should be the **threat interpreter**, not the query writer.
Your code should remain the **S1 detection engineer**.
