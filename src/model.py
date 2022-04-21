from typing import Any, List
from pynamodb.attributes import (
    UnicodeAttribute, 
    ListAttribute, 
    MapAttribute, 
    NumberAttribute, 
    UTCDateTimeAttribute,
    BooleanAttribute,
)
from pynamodb.models import Model
from datetime import datetime
import boto3
from boto3.dynamodb.conditions import Key, Attr


class User(Model):
    class Meta:
        table_name = "users"
        region = "ap-south-1"

    email = UnicodeAttribute(hash_key=True, null=False)
    username = UnicodeAttribute(null=False)
    password = UnicodeAttribute(null=False)
    total_accounts = NumberAttribute(null=False, default=0)
    createdAt = UTCDateTimeAttribute(null=False, default=datetime.now())
    verified = BooleanAttribute(null=False, default=False)

class PasswordSaver(Model):
    class Meta:
        table_name = "password_saver"
        region = "ap-south-1"

    accountId = UnicodeAttribute(hash_key=True, null=False)
    userID = UnicodeAttribute(null=False)
    account = UnicodeAttribute(null=False)
    username = UnicodeAttribute(null=False)
    password = UnicodeAttribute(null=False)
    addedAt = UTCDateTimeAttribute(null=False, default=datetime.now())


class Pagination:
    def __init__(self, table_name:str, select_field:str, equal_to:Any, get_field:List[Any]=None) -> None:
        self.select_field = select_field
        self.equal_to = equal_to
        self.get_field = ", ".join(get_field)
        self.__dynamodb = boto3.resource('dynamodb')
        self.__table = self.__dynamodb.Table(table_name)

    def paginate(self, last_key=None, limit=10):
        if last_key is not None and self.get_field is not None:
            response = self.__table.scan(
                FilterExpression=Attr(self.select_field).eq(self.equal_to),
                ExclusiveStartKey=last_key,
                Limit=limit, 
                ProjectionExpression= self.get_field
            )
        elif last_key is None and self.get_field is not None:
            response = self.__table.scan(
                FilterExpression=Attr(self.select_field).eq(self.equal_to),
                Limit=limit,
                ProjectionExpression= self.get_field
            )
        elif last_key is not None and self.get_field is None:
            response = self.__table.scan(
                FilterExpression=Attr(self.select_field).eq(self.equal_to),
                ExclusiveStartKey=last_key,
                Limit=limit
            )
        else:
            response = self.__table.scan(
                FilterExpression=Attr(self.select_field).eq(self.equal_to),
                Limit=limit
            )
        
        return response['Items'], response.get('LastEvaluatedKey', None)
