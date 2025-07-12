from flask import Flask, request, jsonify
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from database import db, User, History
import bcrypt

app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'

db.init_app(app)
jwt = JWTManager(app)
CORS(app)

with app.app_context():
    db.create_all()

# Model ve tokenizer
#model_name = "../model" #local
model_name = "panagoa/nllb-200-1.3b-kbd-v0.2" #huggingface
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSeq2SeqLM.from_pretrained(model_name)


LANG_CODES = {
    "Türkçe": "tur_Latn",
    "Çerkesce (Doğu)": "kbd_Cyrl",

}

@app.route('/register',methods =['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message' : 'Kullanıcı adı ve şifre gerekli'}),400
    if User.query.filter_by(username = username).first():
        return jsonify({'message':'kullanıcı adı zaten alınmış'}),400
    
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(username=username, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message':'kullanıcı oluştururldu'}),201

@app.route('/login',methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username = username).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'),user.password_hash.encode('utf-8')):
        return jsonify({'message':'kullanıcı adı veya şifre hatalı'}),401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({'access_token':access_token}),200


@app.route("/translateByLogin", methods=["POST"])
@jwt_required()
def translateByLogin():
    user_id = get_jwt_identity()
    data = request.get_json()
    text = data.get("text", "").strip()
    source_lang = data.get("source_lang", "Kabardeyce")
    target_lang = data.get("target_lang", "Türkçe")

    if not text:
        return jsonify({"error": "Metin boş olamaz."}), 400

    src_code = LANG_CODES.get(source_lang)
    tgt_code = LANG_CODES.get(target_lang)

    if not src_code or not tgt_code:
        return jsonify({"error": "Dil kodu tanınmadı."}), 400

    # Geçmişten çeviri kontrolü
    existing_history = History.query.filter_by(
        input_text=text,
        source_lang=source_lang,
        target_lang=target_lang,
        user_id=user_id
    ).first()

    if existing_history:
        return jsonify({"çeviri": existing_history.target_text, "kaynak": "veritabanı"})

    try:
        # Model ile çevir
        inputs = tokenizer(f"{src_code}: {text}", return_tensors="pt")
        translated_tokens = model.generate(
            **inputs,
            forced_bos_token_id=tokenizer.lang_code_to_id[tgt_code],
            max_length=50
        )
        translation = tokenizer.batch_decode(translated_tokens, skip_special_tokens=True)[0]

        # Veritabanına kaydet
        new_history = History(
            input_text=text,
            target_text=translation,
            source_lang=source_lang,
            target_lang=target_lang,
            user_id=user_id
        )
        db.session.add(new_history)
        db.session.commit()

        return jsonify({"çeviri": translation, "kaynak": "model"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/translate", methods=["POST"])
def translate():
    data = request.get_json()
    text = data.get("text", "").strip()
    source_lang = data.get("source_lang", "Kabardeyce")
    target_lang = data.get("target_lang", "Türkçe")

    if not text:
        return jsonify({"error": "Metin boş olamaz."}), 400

    src_code = LANG_CODES.get(source_lang)
    tgt_code = LANG_CODES.get(target_lang)

    if not src_code or not tgt_code:
        return jsonify({"error": "Dil kodu tanınmadı."}), 400

    try:
        # Model ile çeviri
        inputs = tokenizer(f"{src_code}: {text}", return_tensors="pt")
        translated_tokens = model.generate(
            **inputs,
            forced_bos_token_id=tokenizer.lang_code_to_id[tgt_code],
            max_length=50
        )
        translation = tokenizer.batch_decode(translated_tokens, skip_special_tokens=True)[0]

        return jsonify({"çeviri": translation, "kaynak": "model"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



if __name__ == "__main__":
    app.run(debug=True, port=5001)
