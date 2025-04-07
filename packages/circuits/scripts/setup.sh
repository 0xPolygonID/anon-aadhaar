# /bin/bash

# Common colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

set -e

download_ptau() {
    local OUTPUT_DIR=$1
    local POWEROFTAU=$2
    
    local CURRENT_DIR=$(pwd)
    
    cd "$OUTPUT_DIR"    
    if [ ! -f powersOfTau28_hez_final_${POWEROFTAU}.ptau ]; then
        echo -e "${YELLOW}Download power of tau....${NC}"
        wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${POWEROFTAU}.ptau
        echo -e "${GREEN}Finished download!${NC}"
    else 
        echo -e "${YELLOW}Powers of tau file already downloaded${NC}"
    fi    
    cd "$CURRENT_DIR"
}

build_circuit_keys() {
    local OUTPUT_DIR=$1
    local CIRCUIT_NAME=$2
    local POWEROFTAU=$3

    echo -e "${BLUE}Building zkey${NC}"
    snarkjs groth16 setup \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}.r1cs \
        ${OUTPUT_DIR}/ptaus/powersOfTau28_hez_final_${POWEROFTAU}.ptau \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}.zkey
    
    local RAND_STR=$(get_random_string)
    echo $RAND_STR | snarkjs zkey contribute \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}.zkey \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_final.zkey

    echo -e "${BLUE}Building vkey${NC}"
    snarkjs zkey export verificationkey \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_final.zkey \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_vkey.json
}

build_circuit_graph() {
    local CIRCUIT_PATH=$1
    local OUTPUT_DIR=$2
    local CIRCUIT_NAME=$3
    local START_TIME=$(date +%s)

    echo -e "${BLUE}Compiling circuit: $CIRCUIT_NAME${NC}"
   
    local circuit_graph_path="${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_graph.wcd"
    
    cargo build --release --manifest-path=circom-witnesscalc/Cargo.toml
    # We have to use local implementation of zk-email with "graph" feature
    time circom-witnesscalc/target/release/build-circuit "$CIRCUIT_PATH" "$circuit_graph_path" -l deps

    cd "$CURRENT_DIR"
}

build_circuit_smart_contract_verifier() {
    local OUTPUT_DIR=$1
    local CIRCUIT_NAME=$2
    local START_TIME=$(date +%s)

    echo -e "${BLUE}Compiling verifier contract: $CIRCUIT_NAME${NC}"
    npx snarkjs zkey export solidityverifier "${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_final.zkey" "${OUTPUT_DIR}/${CIRCUIT_NAME}/contracts/Verifier.sol"
    echo "Contracts generated!"
}

get_random_string() {
    if command -v openssl &> /dev/null; then
        echo $(openssl rand -hex 64)
    else
        echo $(date +%s)
    fi
}

# Warning: AnonAadhaar uses custom implementation of @zk-email circuits that was not published yet
build_circuit() {
    local CIRCUIT_NAME=$1
    local POWEROFTAU=$2
    local OUTPUT_DIR=$3
    local START_TIME=$(date +%s)

    echo -e "${BLUE}Compiling circuit: $CIRCUIT_NAME${NC}"
    
    # Create output directory
    mkdir -p ${OUTPUT_DIR}/${CIRCUIT_NAME}/contracts
    
    # Download power of tau
    if [ ! -f ${OUTPUT_DIR}/ptaus/powersOfTau28_hez_final_${POWEROFTAU}.ptau ] ; then
        mkdir -p ${OUTPUT_DIR}/ptaus
        download_ptau $OUTPUT_DIR/ptaus $POWEROFTAU
    fi
    
    # Compile circuit
    local CIRCUIT_PATH="$(pwd)/packages/circuits/src/${CIRCUIT_NAME}.circom"
    circom ${CIRCUIT_PATH} -l deps --r1cs --wasm -c --output ${OUTPUT_DIR}/${CIRCUIT_NAME}/
    build_circuit_keys $OUTPUT_DIR $CIRCUIT_NAME $POWEROFTAU
    build_circuit_graph $CIRCUIT_PATH $OUTPUT_DIR $CIRCUIT_NAME
    build_circuit_smart_contract_verifier $OUTPUT_DIR $CIRCUIT_NAME
    
    # Print build statistics
    echo -e "${GREEN}Build of $CIRCUIT_NAME completed in $(($(date +%s) - START_TIME)) seconds${NC}"
    echo -e "${BLUE}Size of ${CIRCUIT_NAME}.r1cs: $(wc -c < ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}.r1cs) bytes${NC}"
    echo -e "${BLUE}Size of ${CIRCUIT_NAME}.wasm: $(wc -c < ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm) bytes${NC}"
    echo -e "${BLUE}Size of ${CIRCUIT_NAME}_final.zkey: $(wc -c < ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_final.zkey) bytes${NC}"
}

build_circuit "aadhaar-verifier" "22" "$(pwd)/packages/circuits/build"