fn main() {
    tonic_build::compile_protos("../tamanoir-common/proto/tamanoir/tamanoir.proto").unwrap();
}
