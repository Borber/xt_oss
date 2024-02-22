use dotenv;
use std::process;
use xt_oss::{
    prelude::*,
    oss::entities::{DataRedundancyType, OssAcl, StorageClass},
    util,
};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    let options = util::options_from_env();
    let client = oss::Client::new(options);
    match client
        .PutBucket()
        .with_acl(OssAcl::PublicRead)
        .with_bucket("xtoss-t1")
        .with_data_redundancy_type(DataRedundancyType::ZRS)
        // .with_group_id("your group_id")
        .with_region("oss-cn-beijing")
        .with_storage_class(StorageClass::Standard)
        .execute()
        .await
        .unwrap_or_else(|error| {
            println!("reqwest error: {}", error);
            process::exit(-1);
        }) {
        Ok(oss_data) => {
            let location = oss_data.headers().get("location").unwrap().to_str().unwrap();
            println!("location: {}", location);
        }
        Err(oss_error_message) => {
            println!("oss error message: {}", oss_error_message.content())
        }
    }
}