from llm_chain import get_sql_for_question

sql_query=get_sql_for_question("list top 5 products from product table ","")
print(type(sql_query))