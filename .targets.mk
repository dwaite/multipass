TARGETS_DRAFTS := draft-template-credential-type draft-waite-jwt-claim-credential draft-waite-multipass-retrieval
TARGETS_TAGS := 
draft-template-credential-type-00.md: draft-template-credential-type.md
	sed -e 's/draft-template-credential-type-latest/draft-template-credential-type-00/g' -e 's/draft-waite-multipass-retrieval-latest/draft-waite-multipass-retrieval-00/g' $< >$@
draft-waite-multipass-retrieval-00.md: draft-waite-multipass-retrieval.md
	sed -e 's/draft-template-credential-type-latest/draft-template-credential-type-00/g' -e 's/draft-waite-multipass-retrieval-latest/draft-waite-multipass-retrieval-00/g' $< >$@
