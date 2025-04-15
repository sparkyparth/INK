from sentence_transformers import SentenceTransformer, util
import pandas as pd

# Load model and data
model = SentenceTransformer('all-MiniLM-L6-v2')
df = pd.read_csv("quotes.csv")  # adjust to your dataset's path and format
quotes = df['quote'].tolist()

# Step 1: Embed all quotes
quote_embeddings = model.encode(quotes, convert_to_tensor=True)

# Step 2: Given a journal entry, find similar quotes
journal = "I feel lost and unmotivated today"
journal_embedding = model.encode(journal, convert_to_tensor=True)

# Step 3: Compute similarity
cos_scores = util.cos_sim(journal_embedding, quote_embeddings)[0]
top_results = cos_scores.topk(5)

for score, idx in zip(top_results[0], top_results[1]):
    print(f"Score: {score:.4f} | Quote: {quotes[idx]}")
