from sqlalchemy.orm import Session
from app.database.models import User, Hymn, Document, DocumentChunk
from app.auth.dependencies import TokenService
from app.services.embedding import EmbeddingService

def seed_database(db: Session):
    """
    Seeds the database with initial MCK data:
    - Default Admin Account
    - Sample Swahili, English, and Kikuyu Hymns
    - Core Methodist Doctrines, History, and Standing Orders (SO 45, 46, etc.)
    """
    print("Checking database seeding status...")

    # 2. Add Default Admin User if not exists
    admin = db.query(User).filter(User.role == "admin").first()
    if not admin:
        print("Seeding default admin user...")
        admin = User(
            email="admin@mck.or.ke",
            password_hash=TokenService.hash_password("adminpassword123"),
            full_name="Conference Admin",
            role="admin"
        )
        db.add(admin)
        db.commit()

    # 3. Add Multilingual Hymns (English, Swahili, Kikuyu)
    hymns_data = [
        # --- English Hymns ---
        {
            "hymn_number": 1,
            "title": "O For a Thousand Tongues to Sing",
            "language": "en",
            "lyrics": "O for a thousand tongues to sing\nMy great Redeemer's praise,\nThe glories of my God and King,\nThe triumphs of his grace!\n\nJesus! the name that charms our fears,\nThat bids our sorrows cease;\n'Tis music in the sinner's ears,\n'Tis life, and health, and peace."
        },
        {
            "hymn_number": 2,
            "title": "To God Be the Glory",
            "language": "en",
            "lyrics": "To God be the glory, great things He hath done,\nSo loved He the world that He gave us His Son,\nWho yielded His life an atonement for sin,\nAnd opened the life gate that all may go in.\n\nPraise the Lord, praise the Lord,\nLet the earth hear His voice!\nPraise the Lord, praise the Lord,\nLet the people rejoice!\nO come to the Father, through Jesus the Son,\nAnd give Him the glory, great things He hath done."
        },
        {
            "hymn_number": 5,
            "title": "Great Is Thy Faithfulness",
            "language": "en",
            "lyrics": "Great is Thy faithfulness, O God my Father;\nThere is no shadow of turning with Thee;\nThou changest not, Thy compassions, they fail not;\nAs Thou hast been, Thou forever wilt be.\n\nGreat is Thy faithfulness! Great is Thy faithfulness!\nMorning by morning new mercies I see;\nAll I have needed Thy hand hath provided;\nGreat is Thy faithfulness, Lord, unto me!"
        },
        {
            "hymn_number": 6,
            "title": "Amazing Grace",
            "language": "en",
            "lyrics": "Amazing grace! How sweet the sound\nThat saved a wretch like me!\nI once was lost, but now am found;\nWas blind, but now I see.\n\n'Twas grace that taught my heart to fear,\nAnd grace my fears relieved;\nHow precious did that grace appear\nThe hour I first believed!"
        },
        # --- Swahili Hymns ---
        {
            "hymn_number": 23,
            "title": "Bwana U Sehemu Yangu",
            "language": "sw",
            "lyrics": "Bwana u sehemu yangu,\nKiongozi cha safari,\nMbele yako ninasimama,\nNiongoze kwa amani.\n\nHata mwisho wa safari,\nUnilinde kwa neema,\nBwana u sehemu yangu,\nSasa na hata milele."
        },
        {
            "hymn_number": 80,
            "title": "Mwamba Wenye Imara",
            "language": "sw",
            "lyrics": "Mwamba wenye imara,\nKwako nitajificha,\nMaji hayo na damu,\nYaliyotoka humu,\nHunisafi na dhambi,\nHunifanya mshindi.\n\nSina cha mkononi,\nNaja msalabani,\nNili tupu, nivike;\nNi mnyonge, nishike;\nNili mchafu naja,\nNioshe nisijafa."
        },
        {
            "hymn_number": 100,
            "title": "Ni Salama Rohoni Mwangu",
            "language": "sw",
            "lyrics": "Nionapo amani kama shwari,\nAma nionapo shida;\nKwa mambo yote umenijulisha,\nNi salama rohoni mwangu.\n\nSalama, salama,\nRohoni, rohoni,\nNi salama rohoni mwangu."
        },
        # --- Kikuyu Hymns ---
        {
            "hymn_number": 50,
            "title": "Ti itherũ twĩ mũrata",
            "language": "kik",
            "lyrics": "Ti itherũ twĩ mũrata,\nŨtahaana ta arĩa angĩ.\nJesũ nĩrĩo rĩtwa rĩake,\nNowe mũtũhoeri.\nKaĩ ũhoro ũcio naguo,\nNĩguo wa magegania.\nAtĩ tũngĩhoya Ngai,\nNdangĩrega kũũigua.\n\nRĩu tũtĩraga nĩkĩ,\nKũmwarĩria kaingĩ ma.\nNĩ tũrĩkanĩre nake,\nTondũ nĩguo endaga.\nOna tũngĩmaatha guothe,\nTuona ũngĩ ta ũyũ.\nAca tũtikoona ũngĩ,\nŨngĩtũigua ta Jesũ."
        },
        {
            "hymn_number": 124,
            "title": "Jesu Njikaria Mũti-inĩ",
            "language": "kik",
            "lyrics": "Jesu Njikaria Mũti-Inĩ,\nGithima-inĩ kĩa ũtugi,\nHe rũũĩ rũa kũhonania,\nRuumaga Gologotha.\n\nMũtĩ-inĩ, mũtĩ-inĩ,\nNdũre ngoocaga Ngai,\nNginya ngoro ĩkahurũka,\nMũrĩmo ũrĩa wa rũũĩ."
        }
    ]

    for h_data in hymns_data:
        existing = db.query(Hymn).filter(
            Hymn.hymn_number == h_data["hymn_number"],
            Hymn.language == h_data["language"]
        ).first()
        if not existing:
            print(f"Seeding Hymn {h_data['hymn_number']} ({h_data['language']})...")
            h = Hymn(**h_data)
            db.add(h)
    db.commit()

    # 4. Add Standing Orders & Doctrines Document if not exists
    doc = db.query(Document).filter(Document.title == "Official Methodist Constitution, History, Doctrines & Standing Orders").first()
    if not doc:
        print("Seeding Methodist Constitution & Doctrines document...")
        doc = Document(
            title="Official Methodist Constitution, History, Doctrines & Standing Orders",
            category="standing_orders",
            language="en",
            is_official=True
        )
        db.add(doc)
        db.commit()
        db.refresh(doc)

        # 5. Core Church Information chunks
        embedding_service = EmbeddingService()
        
        doctrinal_data = [
            {
                "tag": "Methodist Doctrine: Baptism",
                "content": "Baptism is a sacrament of the New Testament, ordained by Jesus Christ. It is a sign of regeneration or new birth, and of the covenant of grace. It represents the wash of sin and reception into the church family. Infants and adults are eligible for baptism in the Methodist Church."
            },
            {
                "tag": "Methodist Doctrine: Holy Communion",
                "content": "The Lord's Supper (Holy Communion) is a sacrament representing our redemption through Christ's death. It is a memorial of Christ's passion, and a sign of Christian love. The table is open to all who love Jesus and earnestly repent of their sins."
            },
            {
                "tag": "Standing Order 1: The Conference",
                "content": "Standing Order 1 defines the Conference. The Conference is the governing body of the Methodist Church Kenya. It consists of the Presiding Bishop, Synod Chairmen, Connexional Officers, and elected lay representatives. The Conference is the final authority on doctrine, discipline, and policy."
            },
            {
                "tag": "Standing Order 45: Local Preachers",
                "content": "Standing Order 45 governs Local Preachers. Candidates for local preachers must be active church members, nominated by the Local Church Committee, and approved by the Circuit Quarterly Meeting. They must undergo trial services and a written examination before full accreditation."
            },
            {
                "tag": "Standing Order 46: Ministers Ordination",
                "content": "Standing Order 46 governs Ministers Ordination. Candidate ministers must complete theological education at an approved seminary, serve as a probationary minister for a minimum of three years, and be recommended by the Synod and approved by the Conference for ordination."
            },
            {
                "tag": "Methodist History: Founder John Wesley",
                "content": "The Methodist movement began in the 18th century within the Church of England, led by John Wesley and his brother Charles Wesley. John Wesley preached salvation by faith, holiness of life, and organized societies divided into classes to encourage mutual accountability and spiritual growth."
            },
            {
                "tag": "Methodist Church Kenya: Leadership Structure",
                "content": "The leadership structure of the Methodist Church Kenya (MCK) is connectional. The highest court is the Conference, led by the Presiding Bishop. Below the Conference are Synods led by Synod Bishops/Chairmen. Synods contain Circuits overseen by Circuit Superintendents, which supervise Local Churches led by Ministers."
            }
        ]

        for index, data in enumerate(doctrinal_data):
            text = f"{data['tag']}\n{data['content']}"
            vector = embedding_service.get_embedding(text)
            
            chunk = DocumentChunk(
                document_id=doc.id,
                chunk_index=index,
                content=text,
                citation_tag=data["tag"],
                embedding=vector
            )
            db.add(chunk)
        
        db.commit()
    print("Database checking/seeding completed successfully.")
