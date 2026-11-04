def ingest_web_pages(vector_store, raw_pages):
    vector_store.add_documents(raw_pages)
