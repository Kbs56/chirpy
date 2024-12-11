# Makefile

# Define the output binary name
OUTPUT = out

# Target for development
dev:
	go build -o $(OUTPUT)
	./$(OUTPUT)

# Clean up the output binary
clean:
	rm -f $(OUTPUT)

.PHONY: dev clean
