idf_component_register(
    SRCS "src/ref/mlkem_wrapper.c"
         "src/ref/kem_ref.c"
         "src/ref/indcpa_ref.c"
         "src/ref/poly_ref.c"
         "src/ref/polyvec_ref.c"
         "src/ref/ntt_ref.c"
         "src/ref/reduce_ref.c"
         "src/ref/cbd_ref.c"
         "src/ref/verify_ref.c"
         "src/ref/symmetric_ref.c"
         "src/ref/fips202_ref.c"
    INCLUDE_DIRS "include" "src/ref"
)

# KYBER_K=2 selects ML-KEM-512
target_compile_definitions(${COMPONENT_LIB} PUBLIC KYBER_K=2)

# Optimization for crypto operations
target_compile_options(${COMPONENT_LIB} PRIVATE -O2 -Wall -Wno-unused-function)
