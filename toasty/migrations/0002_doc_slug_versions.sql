DROP INDEX "index_doc_articles_by_slug";
CREATE INDEX "index_doc_articles_by_slug" ON "doc_articles" ("slug");
