package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/kataras/go-sessions"
	// "os"
)

var db *sql.DB
var err error

type user struct {
	ID        int
	Username  string
	FirstName string
	Password  string
}

type dsn struct {
	IDdsn       int
	KodeDosen   string
	NamaDosen   string
	Passworddsn string
}

type adm struct {
	IDadm       int
	Email       string
	Name        string
	Passwordadm string
}

type JadMk struct {
	IdJadwal      int
	KodeMk        string
	KodeDosen     string
	JumlahPeserta int
}

type krs struct {
	IDkrs    int
	IdJadwal int
	NIM      string
}

type Mk struct {
	IdMk   int
	KodeMk string
	NamaMk string
	Sks    int
}
type peserta struct {
	IdJadwal      int
	JumlahPeserta int
}

func connect_db() {
	db, err = sql.Open("mysql", "root:@tcp(127.0.0.1)/web_semester_antara")

	if err != nil {
		log.Fatalln(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalln(err)
	}
}

func routes() {
	http.Handle("/resources/css/", http.StripPrefix("/resources/css/", http.FileServer(http.Dir("./views/resources/css"))))
	http.Handle("/resources/js/", http.StripPrefix("/resources/js/", http.FileServer(http.Dir("./views/resources/js"))))

	// mahasiswa
	http.HandleFunc("/", home)
	http.HandleFunc("/mahasiswa/daftarMk", DaftarSemester)
	http.HandleFunc("/mahasiswa/daftar", DaftarKrs)
	// dosen
	http.HandleFunc("/dosen", homeDosen)
	http.HandleFunc("/dosen/Mk", dosenMataKuliah)
	// admin
	http.HandleFunc("/admin", homeAdmin)
	http.HandleFunc("/admin/mahasiswa", mahasiswa)
	http.HandleFunc("/admin/dosen", dosen)
	http.HandleFunc("/admin/JadwalMk", JadwalMk)
	http.HandleFunc("/admin/Mk", ListMk)
	http.HandleFunc("/admin/delete", Delete)
	http.HandleFunc("/admin/add", Add)
	http.HandleFunc("/admin/add-user/exec", AddExec)
	http.HandleFunc("/admin/edit", Edit)
	http.HandleFunc("/admin/edit/execute", EditExec)
	http.HandleFunc("/admin/add-jadwal", AddJdl)
	http.HandleFunc("/admin/add-jadwal/exec", AddJdlExec)
	http.HandleFunc("/admin/edit-jadwal", EditJdl)
	http.HandleFunc("/admin/edit-jadwal/exec", EditJdlExec)
	http.HandleFunc("/admin/delete-jadwal", DeleteJdl)
	http.HandleFunc("/admin/addmk", AddMk)
	http.HandleFunc("/admin/addmk/exec", AddMkExec)
	http.HandleFunc("/admin/editmk", EditMk)
	http.HandleFunc("/admin/editmk/exec", EditMkExec)
	http.HandleFunc("/admin/deletemk", DeleteMk)

	// sistem
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
}

func getAllMahasiswa() []user {
	rows, err := db.Query(`SELECT * FROM mahasiswa`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var mahasiswa []user

	for rows.Next() {
		var mhsiswa user
		if err := rows.Scan(&mhsiswa.ID, &mhsiswa.Username, &mhsiswa.FirstName, &mhsiswa.Password); err != nil {
			panic(err)
		}

		mahasiswa = append(mahasiswa, mhsiswa)
	}

	return mahasiswa
}
func getAllDosen() []dsn {
	rows, err := db.Query(`SELECT * FROM dosen`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var dosent []dsn

	for rows.Next() {
		var dosen dsn
		if err := rows.Scan(&dosen.IDdsn, &dosen.NamaDosen, &dosen.KodeDosen, &dosen.Passworddsn); err != nil {
			panic(err)
		}

		dosent = append(dosent, dosen)
	}

	return dosent
}
func getAllAdmin() []adm {
	rows, err := db.Query(`SELECT * FROM admin`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var admint []adm

	for rows.Next() {
		var admin adm
		if err := rows.Scan(&admin.IDadm, &admin.Email, &admin.Name, &admin.Passwordadm); err != nil {
			panic(err)
		}

		admint = append(admint, admin)
	}

	return admint
}
func getAllJadMk() []JadMk {
	rows, err := db.Query(`SELECT * FROM jadwal_mk`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var admint []JadMk

	for rows.Next() {
		var admin JadMk
		if err := rows.Scan(&admin.IdJadwal, &admin.KodeMk, &admin.KodeDosen, &admin.JumlahPeserta); err != nil {
			panic(err)
		}

		admint = append(admint, admin)
	}

	return admint
}
func getAllMk() []Mk {
	rows, err := db.Query(`SELECT * FROM mata_kuliah`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var admint []Mk

	for rows.Next() {
		var admin Mk
		if err := rows.Scan(&admin.IdMk, &admin.KodeMk, &admin.NamaMk, &admin.Sks); err != nil {
			panic(err)
		}

		admint = append(admint, admin)
	}

	return admint
}

func main() {
	connect_db()
	routes()

	defer db.Close()

	fmt.Println("Server running on port :1229")
	http.ListenAndServe(":1229", nil)
}

func checkErr(w http.ResponseWriter, r *http.Request, err error) bool {
	if err != nil {

		fmt.Println(r.Host + r.URL.Path)

		http.Redirect(w, r, r.Host+r.URL.Path, 301)
		return false
	}

	return true
}

func jumlahPeserta(idJadwal any) int {
	var peserta = peserta{}
	err = db.QueryRow(`
		SELECT COUNT(id_jadwal)
		AS jumlah_peserta
		FROM krs WHERE id_jadwal=?
	`, idJadwal).
		Scan(
			&peserta.JumlahPeserta,
		)
	if err != nil {
		log.Println(err)
	}

	stmt, err := db.Prepare("UPDATE jadwal_mk SET jumlah_peserta=? WHERE id_jadwal=?")
	if err == nil {
		_, err = stmt.Exec(peserta.JumlahPeserta, &idJadwal)
		if err != nil {
			log.Fatal(err)
		}
	}

	// fmt.Println(peserta.JumlahPeserta)
	return peserta.JumlahPeserta
}

func QueryKrs(qkrs string) []krs {
	rows, err := db.Query(`SELECT * FROM krs WHERE nim=?`, qkrs)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var admint []krs

	for rows.Next() {
		var admin krs
		if err := rows.Scan(&admin.IDkrs, &admin.IdJadwal, &admin.NIM); err != nil {
			panic(err)
		}

		admint = append(admint, admin)
	}

	return admint
}

func Queryjdl(jdl any) JadMk {
	var JadMk = JadMk{}
	err = db.QueryRow(`
		select id_jadwal,
		kode_mk,
		kode_dosen
		FROM jadwal_mk WHERE id_jadwal=?
	`, jdl).
		Scan(
			&JadMk.IdJadwal,
			&JadMk.KodeMk,
			&JadMk.KodeDosen,
		)
	if err != nil {
		log.Println(err)
	}
	return JadMk
}

func QueryjdlViaMK(kmk string) JadMk {
	var JadMk = JadMk{}
	err = db.QueryRow(`
		select id_jadwal,
		kode_mk,
		kode_dosen
		FROM jadwal_mk WHERE kode_mk=?
	`, kmk).
		Scan(
			&JadMk.IdJadwal,
			&JadMk.KodeMk,
			&JadMk.KodeDosen,
		)
	if err != nil {
		log.Println(err)
	}
	return JadMk
}

func Querymatkul(kmk string) Mk {
	var Mk = Mk{}
	err = db.QueryRow(`
		select id,
		kode_mk,
		nama_mk,   
		sks
		FROM mata_kuliah WHERE kode_mk=?
	`, kmk).
		Scan(
			&Mk.IdMk,
			&Mk.KodeMk,
			&Mk.NamaMk,
			&Mk.Sks,
		)
	return Mk
}

func QueryUser(username string) user {
	var users = user{}
	err = db.QueryRow(`
		SELECT id, 
		NIM, 
		name,  
		password 
		FROM mahasiswa WHERE NIM=?
		`, username).
		Scan(
			&users.ID,
			&users.Username,
			&users.FirstName,
			&users.Password,
		)
	return users
}

func QueryDosen(username string) dsn {
	var dosen = dsn{}
	err = db.QueryRow(`
		SELECT id, 
		kode_dosen, 
		nama_dosen,  
		password 
		FROM dosen WHERE kode_dosen=?
		`, username).
		Scan(
			&dosen.IDdsn,
			&dosen.KodeDosen,
			&dosen.NamaDosen,
			&dosen.Passworddsn,
		)
	return dosen
}
func QueryAdmin(username string) adm {
	var admin = adm{}
	err = db.QueryRow(`
		SELECT id, 
		email, 
		name,  
		password 
		FROM admin WHERE email=?
		`, username).
		Scan(
			&admin.IDadm,
			&admin.Email,
			&admin.Name,
			&admin.Passwordadm,
		)
	return admin
}

func home(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	if len(session.GetString("username")) == 0 {
		http.Redirect(w, r, "/login", 301)
	}

	kartuRencanaStudi := QueryKrs(session.GetString("username"))

	funcMap := template.FuncMap{
		"increment": func(i int) int {
			i += 1
			return i
		},

		"querynamamk": func(kodeMK string) string {
			kirito := Querymatkul(kodeMK)
			return kirito.NamaMk
		},

		"queryjadul": func(IdJadwal int) int {
			jadwal := Queryjdl(IdJadwal)
			return jadwal.IdJadwal
		},

		"querykmk": func(idJadwal any) any {
			kmk := Queryjdl(idJadwal)
			return kmk.KodeMk
		},

		"qjumlahpeserta": func(idjadwal any) int {
			jump := jumlahPeserta(idjadwal)
			return jump
		},
	}

	// var kanjs krs
	var data = map[string]any{
		"username": session.GetString("name"),
		"nim":      session.GetString("username"),
		"krs":      kartuRencanaStudi,
	}

	var t = template.New("home.html").Funcs(funcMap)

	t, err = t.ParseFiles("views/mahasiswa/home.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

}

func homeDosen(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	if len(session.GetString("username")) == 0 {
		http.Redirect(w, r, "/login", 301)
	}
	JadMk := getAllJadMk()

	var data = map[string]any{
		"username": session.GetString("name"),
		"kdsn":     session.GetString("username"),
		"JadMk":    JadMk,
	}
	var t, err = template.ParseFiles("views/dosen/dosen-jadwal-mk.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	return
}

func DaftarSemester(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	mk := getAllMk()

	var sudahDaftar bool
	cekPendaftaran := QueryKrs(session.GetString("username"))
	// fmt.Println(cekPendaftaran)

	if cekPendaftaran != nil {
		sudahDaftar = true
	} else {
		sudahDaftar = false
	}

	// fmt.Println(sudahDaftar)

	funcMap := template.FuncMap{
		"increment": func(i int) int {
			i += 1
			return i
		},

		"queryjadwal": func(kmk string) any {
			idJadwal := QueryjdlViaMK(kmk)
			return idJadwal.IdJadwal
		},
	}

	var data = map[string]any{
		"username":    session.GetString("name"),
		"nim":         session.GetString("username"),
		"Mk":          mk,
		"sudahDaftar": sudahDaftar,
	}

	var t = template.New("daftarMk.html").Funcs(funcMap)

	t, err = t.ParseFiles("views/mahasiswa/daftarMk.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
}

func DaftarKrs(w http.ResponseWriter, r *http.Request) { // daftar krs jalan
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	nim := r.FormValue("nim")
	jadwal1 := r.FormValue("jadwal1")
	jadwal2 := r.FormValue("jadwal2")
	jadwal3 := r.FormValue("jadwal3")

	if jadwal1 != "" {
		stmt, err := db.Prepare("INSERT INTO krs SET id_jadwal=?, nim=?")
		if err == nil {
			_, err = stmt.Exec(&jadwal1, &nim)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		}
	}

	if jadwal2 != "" {
		stmt, err := db.Prepare("INSERT INTO krs SET id_jadwal=?, nim=?")
		if err == nil {
			_, err = stmt.Exec(&jadwal2, &nim)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		}
	}

	if jadwal3 != "" {
		stmt, err := db.Prepare("INSERT INTO krs SET id_jadwal=?, nim=?")
		if err == nil {
			_, err = stmt.Exec(&jadwal3, &nim)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

		}
	}

	http.Redirect(w, r, "/mahasiswa/daftarMk", http.StatusSeeOther)
	return
}

func dosenMataKuliah(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	// if len(session.GetString("username")) == 0 {
	// 	http.Redirect(w, r, "/login", 301)
	// }
	Mk := getAllMk()

	var data = map[string]any{
		"username": session.GetString("name"),
		"kdsn":     session.GetString("username"),
		"Mk":       Mk,
	}
	var t, err = template.ParseFiles("views/dosen/mk-dosen.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	return
}

//ADMIN

func mahasiswa(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	nim := session.GetString("username")

	fmt.Println(session)
	if len(nim) == 0 {
		http.Redirect(w, r, "/login", 301)
	}

	mahasiswa := getAllMahasiswa()

	var data = map[string]any{
		"username":  session.GetString("name"),
		"nim":       nim,
		"message":   "weh mas admin",
		"mahasiswa": mahasiswa,
	}
	var t, err = template.ParseFiles("views/admin-user/mahasiswa.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	return
}

func dosen(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	fmt.Println(session)
	if len(session.GetString("username")) == 0 {
		http.Redirect(w, r, "/login", 301)
	}

	dosen := getAllDosen()

	var data = map[string]any{
		"username": session.GetString("name"),
		"message":  "weh mas admin",
		"dosen":    dosen,
	}
	var t, err = template.ParseFiles("views/admin-user/adminDosen.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	return
}

func homeAdmin(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	if len(session.GetString("username")) == 0 {
		http.Redirect(w, r, "/login", 301)
	}

	admin := getAllAdmin()

	var data = map[string]any{
		"username": session.GetString("name"),
		"message":  "weh mas admin",
		"admin":    admin,
	}
	var t, err = template.ParseFiles("views/admin.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	session.Set("username", session.GetString("username"))
	return

}

func JadwalMk(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	JadMk := getAllJadMk()

	var data = map[string]any{
		"username": session.GetString("name"),
		"message":  "weh mas admin",
		"JadMk":    JadMk,
	}
	var t, err = template.ParseFiles("views/admin-user/jadwal_mk.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	session.Set("username", session.GetString("username"))
	return
}
func ListMk(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	Mk := getAllMk()

	var data = map[string]any{
		"username": session.GetString("name"),
		"message":  "weh mas admin",
		"Mk":       Mk,
	}
	var t, err = template.ParseFiles("views/admin-user/mk.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	return
}

func Add(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		temp, err := template.ParseFiles("add.html")
		if err != nil {
			panic(err)
		}

		temp.Execute(w, nil)
		return
	}
}

func AddExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	name := r.FormValue("name")
	password := r.FormValue("password")

	UserType := r.FormValue("usertype")

	switch UserType {
	case "admin":
		admin := QueryAdmin(username)
		if (adm{}) == admin {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("INSERT INTO admin SET email=?, name=?, password=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &password)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			http.Redirect(w, r, "/admin", http.StatusFound)
		}

	case "dosen":
		dosen := QueryDosen(username)
		if (dsn{}) == dosen {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("INSERT INTO dosen SET kode_dosen=?, nama_dosen=?, password=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &password)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			http.Redirect(w, r, "/admin", http.StatusFound)
		}

	case "mahasiswa":
		mahasiswa := QueryUser(username)
		if (user{}) == mahasiswa {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("INSERT INTO mahasiswa SET NIM=?, name=?, password=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &password)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			http.Redirect(w, r, "/admin", http.StatusFound)
		}
	}
}

func Edit(w http.ResponseWriter, r *http.Request) {
	userType := r.URL.Query().Get("ut")
	if userType == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	idString := r.URL.Query().Get("id")
	id, errs := strconv.Atoi(idString)
	if errs != nil {
		panic(errs)
	}

	switch userType {
	case "mahasiswa":
		var users = user{}
		err = db.QueryRow(`
		SELECT id, 
		NIM, 
		name,  
		password 
		FROM mahasiswa WHERE id=?
		`, id).
			Scan(
				&users.ID,
				&users.Username,
				&users.FirstName,
				&users.Password,
			)

		username := users.Username
		name := users.FirstName

		var data = map[string]any{
			"usertype": userType,
			"id":       id,
			"username": username,
			"name":     name,
		}

		var t, err = template.ParseFiles("views/admin-user/edituser.html")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		t.Execute(w, data)
		return

	case "dosen":
		var dosen = dsn{}
		err = db.QueryRow(`
		SELECT id, 
		kode_dosen, 
		nama_dosen,  
		password 
		FROM dosen WHERE id=?
		`, id).
			Scan(
				&dosen.IDdsn,
				&dosen.KodeDosen,
				&dosen.NamaDosen,
				&dosen.Passworddsn,
			)

		username := dosen.KodeDosen
		name := dosen.NamaDosen

		var data = map[string]any{
			"usertype": userType,
			"id":       id,
			"username": username,
			"name":     name,
		}

		var t, err = template.ParseFiles("views/admin-user/edituser.html")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		t.Execute(w, data)
		return

	case "admin":
		var admin = adm{}
		err = db.QueryRow(`
		SELECT id, 
		email, 
		name,  
		password 
		FROM admin WHERE id=?
		`, id).
			Scan(
				&admin.IDadm,
				&admin.Email,
				&admin.Name,
				&admin.Passwordadm,
			)

		username := admin.Email
		name := admin.Name

		var data = map[string]any{
			"usertype": userType,
			"id":       id,
			"username": username,
			"name":     name,
		}

		var t, err = template.ParseFiles("views/admin-user/edituser.html")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		t.Execute(w, data)
		return
	}

}

func EditExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	id := r.FormValue("id")
	username := r.FormValue("username")
	name := r.FormValue("name")
	password := r.FormValue("password")

	UserType := r.FormValue("utype")

	switch UserType {
	case "admin":
		if len(password) != 0 {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("UPDATE admin SET email=?, name=?, password=? WHERE id=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &hashedPassword, &id)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			stmt, err := db.Prepare("UPDATE admin SET email=?, name=? WHERE id=?")
			if err == nil {
				_, err = stmt.Exec(&username, &name, &id)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}
		}

	case "dosen":
		if len(password) != 0 {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("UPDATE dosen SET kode_dosen=?, nama_dosen=?, password=? WHERE id=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &hashedPassword, &id)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			stmt, err := db.Prepare("UPDATE dosen SET kode_dosen=?, nama_dosen=? WHERE id=?")
			if err == nil {
				_, err = stmt.Exec(&username, &name, &id)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}
		}

	case "mahasiswa":
		if len(password) != 0 {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("UPDATE mahasiswa SET NIM=?, name=?, password=? WHERE id=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &hashedPassword, &id)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			stmt, err := db.Prepare("UPDATE mahasiswa SET NIM=?, name=? WHERE id=?")
			if err == nil {
				_, err = stmt.Exec(&username, &name, &id)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}
		}
	}
}

func Delete(w http.ResponseWriter, r *http.Request) {
	UserType := r.URL.Query().Get("ut")
	if UserType == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	idString := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idString)
	if err != nil {
		panic(err)
	}

	query := fmt.Sprintf("DELETE FROM %s WHERE id = ?", UserType)

	_, errs := db.Exec(query, id)
	if errs != nil {
		panic(errs)
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func AddJdl(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		temp, err := template.ParseFiles("addjdl.html")
		if err != nil {
			panic(err)
		}

		temp.Execute(w, nil)
		return
	}
}

func AddJdlExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	kmk := r.FormValue("kode_mk")
	kdsn := r.FormValue("kodedsn")

	stmt, err := db.Prepare("INSERT INTO jadwal_mk SET kode_mk=?, kode_dosen=?")
	if err == nil {
		_, err = stmt.Exec(&kmk, &kdsn)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
}

func EditJdl(w http.ResponseWriter, r *http.Request) {
	idJdl := r.URL.Query().Get("q")
	if idJdl == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	idString := r.URL.Query().Get("q")
	id, errs := strconv.Atoi(idString)
	if errs != nil {
		panic(errs)
	}

	var JadwalMk = JadMk{}
	err = db.QueryRow(`
		SELECT id_jadwal, 
		kode_mk, 
		kode_dosen
		FROM jadwal_mk WHERE id_jadwal=?
		`, id).
		Scan(
			&JadwalMk.IdJadwal,
			&JadwalMk.KodeDosen,
			&JadwalMk.KodeMk,
		)

	kodeDosen := JadwalMk.KodeDosen
	kodeMk := JadwalMk.KodeMk
	var data = map[string]any{
		"idJadwal":  id,
		"kodeDosen": kodeDosen,
		"kodeMk":    kodeMk,
	}

	var t, err = template.ParseFiles("views/admin-user/editjdl.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	return

}

func EditJdlExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	id := r.FormValue("id")
	kdsn := r.FormValue("kdsn")
	kmk := r.FormValue("kmk")

	stmt, err := db.Prepare("UPDATE jadwal_mk SET kode_dosen=?, kode_mk=? WHERE id_jadwal=?")
	if err == nil {
		_, err = stmt.Exec(&kdsn, &kmk, &id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

}

func DeleteJdl(w http.ResponseWriter, r *http.Request) {
	UserType := r.URL.Query().Get("q")
	if UserType == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	idString := r.URL.Query().Get("q")
	id, err := strconv.Atoi(idString)
	if err != nil {
		panic(err)
	}

	_, errs := db.Exec("DELETE FROM jadwal_mk WHERE id_jadwal = ?", id)
	if errs != nil {
		panic(errs)
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func AddMk(w http.ResponseWriter, r *http.Request) {

	var t, err = template.ParseFiles("addmk.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, nil)
	return
}

func AddMkExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	kmk := r.FormValue("kmk")
	nmk := r.FormValue("nmk")
	sks := r.FormValue("sks")

	stmt, err := db.Prepare("INSERT INTO mata_kuliah SET kode_mk=?, nama_mk=?, sks=?")
	if err == nil {
		_, err = stmt.Exec(&kmk, &nmk, &sks)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
}

func EditMk(w http.ResponseWriter, r *http.Request) {
	idMk := r.URL.Query().Get("q")
	if idMk == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	idString := r.URL.Query().Get("q")
	id, errs := strconv.Atoi(idString)
	if errs != nil {
		panic(errs)
	}

	var Mk = Mk{}
	err = db.QueryRow(`
		SELECT id, 
		kode_mk, 
		nama_mk,
		sks
		FROM mata_kuliah WHERE id=?
		`, id).
		Scan(
			&Mk.IdMk,
			&Mk.KodeMk,
			&Mk.NamaMk,
			&Mk.Sks,
		)
	kode_mk := Mk.KodeMk
	nama_mk := Mk.NamaMk
	sks := Mk.Sks
	var data = map[string]any{
		"IdMk":   id,
		"kodeMk": kode_mk,
		"NamaMk": nama_mk,
		"sks":    sks,
	}

	var t, err = template.ParseFiles("views/admin-user/editmk.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Execute(w, data)
	return
}

func EditMkExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	id := r.FormValue("id")
	kmk := r.FormValue("kmk")
	nmk := r.FormValue("nmk")
	sks := r.FormValue("sks")

	stmt, err := db.Prepare("UPDATE mata_kuliah SET kode_mk=?, nama_mk=?, sks=? WHERE id=?")
	if err == nil {
		_, err = stmt.Exec(&kmk, &nmk, &sks, &id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

}

func DeleteMk(w http.ResponseWriter, r *http.Request) {
	UserType := r.URL.Query().Get("q")
	if UserType == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	idString := r.URL.Query().Get("q")
	id, err := strconv.Atoi(idString)
	if err != nil {
		panic(err)
	}

	_, errs := db.Exec("DELETE FROM mata_kuliah WHERE id = ?", id)
	if errs != nil {
		panic(errs)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
	return
}

//ADMIN END

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.ServeFile(w, r, "views/register.html")
		return
	}

	username := r.FormValue("email")
	first_name := r.FormValue("first_name")
	// last_name := r.FormValue("last_name")
	password := r.FormValue("password")

	users := QueryUser(username)

	if (user{}) == users {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		if len(hashedPassword) != 0 && checkErr(w, r, err) {
			stmt, err := db.Prepare("INSERT INTO mahasiswa SET NIM=?, password=?, name=?")
			if err == nil {
				_, err := stmt.Exec(&username, &hashedPassword, &first_name)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}
	} else {
		http.Redirect(w, r, "/register", 302)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	if len(session.GetString("username")) != 0 && checkErr(w, r, err) {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method != "POST" {
		http.ServeFile(w, r, "views/login.html")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	usertype := r.FormValue("user")

	users := QueryUser(username)
	dosen := QueryDosen(username)
	admin := QueryAdmin(username)

	switch usertype {
	case "mahasiswa":
		//deskripsi dan compare password
		var password_tes = bcrypt.CompareHashAndPassword([]byte(users.Password), []byte(password))

		if password_tes == nil {
			//login success
			session := sessions.Start(w, r)
			session.Set("username", users.Username)
			session.Set("name", users.FirstName)
			http.Redirect(w, r, "/", 302)
		} else {
			//login failed
			http.Redirect(w, r, "/login", 302)
		}
		return
	case "dosen":
		//deskripsi dan compare password
		var password_tes = bcrypt.CompareHashAndPassword([]byte(dosen.Passworddsn), []byte(password))

		if password_tes == nil {
			//login success
			session := sessions.Start(w, r)
			session.Set("username", dosen.KodeDosen)
			session.Set("name", dosen.NamaDosen)
			http.Redirect(w, r, "/dosen", 302)
		} else {
			//login failed
			http.Redirect(w, r, "/login", 302)
		}
		return
	case "admin":
		//deskripsi dan compare password
		var password_tes = bcrypt.CompareHashAndPassword([]byte(admin.Passwordadm), []byte(password))

		if password_tes == nil {
			//login success
			session := sessions.Start(w, r)
			session.Set("username", admin.Email)
			session.Set("name", admin.Name)
			http.Redirect(w, r, "/admin", 302)
		} else {
			//login failed
			http.Redirect(w, r, "/login", 302)
		}
		return
	}

	//deskripsi dan compare password
	var password_tes = bcrypt.CompareHashAndPassword([]byte(users.Password), []byte(password))

	if password_tes == nil {

		//login success
		session := sessions.Start(w, r)
		session.Set("username", users.Username)
		session.Set("name", users.FirstName)
		http.Redirect(w, r, "/", 302)

	} else {
		//login failed
		http.Redirect(w, r, "/login", 302)
	}

}
func logout(w http.ResponseWriter, r *http.Request) {
	session := sessions.Start(w, r)
	session.Clear()
	sessions.Destroy(w, r)
	http.Redirect(w, r, "/", 302)
}
