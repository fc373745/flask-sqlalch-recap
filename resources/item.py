from flask_jwt import JWT, jwt_required
from flask_restful import Resource, reqparse

from models.item import ItemModel


class Item(Resource):

    @jwt_required()
    def get(self, name):
        # return {"items": ItemModel.query.all()}
        item = ItemModel.find_by_name(name)
        if item:
            return item.json()
        return {'message': 'Item does not exist'}, 404

    def post(self, name):
        if ItemModel.find_by_name(name):
            return {
                "message": "an item with name {} already exists".format(name)
            }, 400
        req = reqparse.RequestParser()
        req.add_argument(
            'price', type=float, required=True, help="need a price field")
        req.add_argument(
            'store_id', type=int, required=True, help="need a store_id field")

        data = req.parse_args()
        item = ItemModel(name, data['price'], data['store_id'])

        try:
            item.save_to_db()
        except:
            return {'message': 'an error occured inserting the item'}, 500

        return item.json(), 201

    def delete(self, name):
        item = ItemModel.find_by_name(name)
        if item:
            item.delete_from_db()

        return {'message': "Item deleted"}
        # connection = sqlite3.connect('data.db')
        # cursor = connection.cursor()

        # query = "DELETE FROM items WHERE name=?"
        # cursor.execute(query, (name, ))

        # connection.commit()
        # connection.close()
        # return {'message': 'Item deleted'}

    def put(self, name):
        parser = reqparse.RequestParser()
        parser.add_argument(
            'price',
            type=float,
            required=True,
            help="This field cannot be left blank!")

        data = parser.parse_args()
        item = ItemModel.find_by_name(name)

        if item is None:
            item = ItemModel(name, data['price'], data['store_id'])
        else:
            item.price = data['price']

        item.save_to_db()
        return item.json()
        # updated_item = {'name': name, 'price': data['price']}

        # if item is None:
        #     try:
        #         updated_item.insert()
        #     except:
        #         return {"message": "an error occured while inserting"}, 500
        # else:
        #     try:
        #         updated_item.update()
        #     except:
        #         return {"message": "an error occured while updating"}, 500
        # return item


class ItemList(Resource):
    def get(self):
        return {"items": [item.json() for item in ItemModel.query.all()]}
        # connection = sqlite3.connect('data.db')
        # cursor = connection.cursor()

        # query = "SELECT * FROM items"
        # res = cursor.execute(query)

        # items = []
        # for row in res:
        #     items.append({'name': row[0], 'price': row[1]})

        # connection.commit()
        # connection.close()

        # return {'items': items}
