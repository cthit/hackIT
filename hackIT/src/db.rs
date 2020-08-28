use diesel::{self, result::QueryResult, prelude::*};
use std::time::SystemTime;

use crate::schema::records;
use crate::schema::records::dsl::{records as all_records};

#[derive(serde::Serialize, Queryable, Debug, Clone)]
pub struct Record {
    pub id: i32,
    pub name: String,
    pub challenge_id: String,
    pub toc: SystemTime,
}

#[table_name="records"]
#[derive(Insertable)]
pub struct RecordForm<'a> {
    pub name : &'a str,
    pub challenge_id : &'a str,
}

impl Record {
    pub fn all(conn: &PgConnection) -> QueryResult<Vec<Record>> {
        all_records.order(records::id.desc()).load::<Record>(conn)
    }

    pub fn insert(conn: &PgConnection, user : &str, challenge_id : &str) -> QueryResult<Record> {

        let recform = RecordForm {name : user, challenge_id : challenge_id};

        diesel::insert_into(all_records).values(recform).get_result::<Record>(conn)
    }

    pub fn get_completion_ids(conn: &PgConnection, user : &str) -> QueryResult<Vec<String>> {
        all_records.order(records::id.desc()).filter(records::name.eq(user)).select(records::challenge_id).load::<String>(conn)
    }

    pub fn has_completed(conn: &PgConnection, user : &str, challenge_id : &str) -> QueryResult<i32> {
        all_records.filter(records::name.eq(user)).filter(records::challenge_id.eq(challenge_id)).select(records::id).first(conn)
    }
}
