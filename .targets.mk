TARGETS_DRAFTS := draft-waite-multipass-retrieval
TARGETS_TAGS := 
draft-waite-multipass-retrieval-00.md: draft-waite-multipass-retrieval.md
	sed -e 's/draft-waite-multipass-retrieval-latest/draft-waite-multipass-retrieval-00/g' -e 's/draft-waite-restricted-jsonld-latest/draft-waite-restricted-jsonld-00/g' $< >$@
draft-waite-restricted-jsonld-00.md: draft-waite-restricted-jsonld.md
	sed -e 's/draft-waite-multipass-retrieval-latest/draft-waite-multipass-retrieval-00/g' -e 's/draft-waite-restricted-jsonld-latest/draft-waite-restricted-jsonld-00/g' $< >$@
