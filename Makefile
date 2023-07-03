# Nome dos diretorios que serao gerados
INCLUDE_D = include
BUILD_D = build
OBJ_D = $(BUILD_D)/obj

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, $(OBJ_D)/%.o, $(SRCS))
BIN = $(BUILD_D)/use_case

# Nome do arquivo zip e arquivos a serem ignorados
ZNAME = Trabalho2_SegComp_2023-1.zip
ZIGNORE = ./$(BUILD_D)/\* 

CC = gcc
CFLAGS = -std=c11 -I$(INCLUDE_D)
LIBS = -lgmp

all: debug

release: CFLAGS += -DNDEBUG -O2
release: $(BIN)

debug: CFLAGS += -g -Wall -Wformat -Wpedantic -fno-omit-frame-pointer
debug: LIBS += -fsanitize=address
debug: $(BIN)

$(OBJS): $(OBJ_D)/%.o: %.c
	@mkdir -p $(@D)
	@echo Compiling $<
	@$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS)
	@$(CC) $(LIBS) $(OBJS) -o $@
	@echo "$(BIN) built successfully!"

clean: 
	@rm -rf $(BUILD_D)
	@echo "Finished cleaning built files"

zip:
	@rm -f $(ZNAME)
	@zip -r $(ZNAME) . -x $(ZIGNORE)
	@echo "Files successfully compressed!"

.PHONY: clean zip
