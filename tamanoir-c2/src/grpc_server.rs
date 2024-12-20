use tamanoir::{
    HelloReply, HelloRequest,
    greeter_server::{Greeter, GreeterServer},
};
use tonic::{Request, Response, Status, transport::Server};

pub mod tamanoir {
    tonic::include_proto!("tamanoir");
}

#[derive(Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request from {:?}", request.remote_addr());

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}
