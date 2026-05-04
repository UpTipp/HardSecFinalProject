# HW_HardwareTrojanLab

Hardware Trojan Insertion Lab - Defensive Analysis

## Files

- `Hardware_Trojan_Insertion_Lab.ipynb` — main lab notebook
- `GHOST_Trojan_GPT.py` — Trojan generation engine (imported by notebook)
- `detector.py` — lightweight heuristic detector for Trojaned Verilog
- `report.pdf` — full lab report covering Tasks 1–5
- `summary.csv` — cross-sample comparison table

## Setup

Install dependencies:

```bash
sudo apt install verilog
```

Also replace the API key, as it may be empty (I left $5 just in case):

```python
os.environ["OPENAI_API_KEY"] = "[INSERT_HERE]"
```

## Running the Notebook

1. Place `GHOST_Trojan_GPT.py` in the same directory as the notebook
2. Run cells top to bottom
3. Generated designs will appear in `./trojaned_outputs/`

## Running the Detector

```bash
python detector.py ./trojaned_outputs/
```

Works recursively, will find all `.v` files in subdirectories.
