package maintenance

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/ivangsm/jay/meta"
)

// Los loops de temporizador del GC y del scrubber eran intesteables: la
// primera pasada del GC llega al minuto y la del scrubber a los 30 s, y
// después cada `interval` (1 h y 6 h en producción). Lo único que se podía
// probar era llamar a RunOnce()/RunIncremental() directo, o sea, todo menos el
// agendado — que es justamente donde estaban los bugs (el drenado muerto del
// timer, el Reset después de NotifyDeletion).
//
// testing/synctest corre el test en una burbuja con reloj falso: synctest.Sleep
// adelanta el tiempo de golpe y synctest.Wait espera a que toda la burbuja
// quede bloqueada. Un test de 25 horas simuladas tarda milisegundos.
//
// Ojo con el reloj falso: la burbuja arranca en 2000-01-01, así que cualquier
// comparación contra el mtime REAL de un archivo en disco da tiempos negativos.
// Por eso estos tests observan la limpieza de multipart (cuyo CreatedAt se
// escribe dentro de la burbuja) y no la de archivos temporales.

// seedStaleUpload deja un multipart upload "initiated" con la marca de tiempo
// del reloj de la burbuja, para que envejezca cuando el test adelante el reloj.
func seedStaleUpload(t *testing.T, db *meta.DB) string {
	t.Helper()
	uploadID := uuid.New().String()
	err := db.CreateMultipartUpload(&meta.MultipartUpload{
		UploadID:  uploadID,
		BucketID:  uuid.New().String(),
		ObjectKey: "abandonado.bin",
		State:     "initiated",
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	return uploadID
}

func uploadExists(t *testing.T, db *meta.DB, uploadID string) bool {
	t.Helper()
	_, err := db.GetMultipartUpload(uploadID)
	if err == nil {
		return true
	}
	if errors.Is(err, meta.ErrUploadNotFound) {
		return false
	}
	t.Fatalf("GetMultipartUpload: %v", err)
	return false
}

// TestGCLoop_FirstPassAtOneMinute fija el agendado del loop del GC: no corre
// nada antes del minuto, y a partir de ahí repite cada `interval`.
func TestGCLoop_FirstPassAtOneMinute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gc, db, _ := testGCWithStore(t, time.Hour)
		uploadID := seedStaleUpload(t, db)

		gc.Start()
		t.Cleanup(gc.Stop)

		synctest.Sleep(59 * time.Second)
		synctest.Wait()
		if n := gc.Passes(); n != 0 {
			t.Fatalf("el GC corrió antes del minuto: %d pasadas", n)
		}

		// Primera pasada exactamente al minuto.
		synctest.Sleep(2 * time.Second)
		synctest.Wait()
		if n := gc.Passes(); n != 1 {
			t.Fatalf("al minuto quiero 1 pasada, tengo %d", n)
		}
		if !uploadExists(t, db, uploadID) {
			t.Fatal("el GC borró un upload que no llegaba a las 24 h")
		}

		// Y después, una pasada por hora.
		synctest.Sleep(3 * time.Hour)
		synctest.Wait()
		if n := gc.Passes(); n != 4 {
			t.Fatalf("tras 3 h más quiero 4 pasadas, tengo %d", n)
		}

		// A las 24 h el upload abandonado se reclama.
		synctest.Sleep(22 * time.Hour)
		synctest.Wait()
		if uploadExists(t, db, uploadID) {
			t.Fatal("el GC nunca reclamó el upload abandonado")
		}
	})
}

// TestGCLoop_NotifyDeletionCorreYaYReagenda cubre la rama que tocó la limpieza
// del drenado muerto del timer: NotifyDeletion dispara una pasada inmediata y
// deja el temporizador reagendado un `interval` completo, sin un disparo
// espurio pegado atrás.
func TestGCLoop_NotifyDeletionCorreYaYReagenda(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gc, db, _ := testGCWithStore(t, time.Hour)

		gc.Start()
		t.Cleanup(gc.Stop)

		// Media hora después de la primera pasada: 1 pasada y contando.
		synctest.Sleep(30 * time.Minute)
		synctest.Wait()
		if n := gc.Passes(); n != 1 {
			t.Fatalf("a los 30 min quiero 1 pasada, tengo %d", n)
		}

		// NotifyDeletion despierta al loop YA, sin esperar el resto del intervalo.
		gc.NotifyDeletion()
		synctest.Wait()
		if n := gc.Passes(); n != 2 {
			t.Fatalf("NotifyDeletion tiene que forzar una pasada inmediata; tengo %d", n)
		}

		// El Reset posterior es un intervalo COMPLETO desde el despertar, no lo
		// que quedaba del anterior: a los 59 min de la notificación todavía no
		// hay pasada nueva, y al pasar la hora sí. Si el Stop()/Reset dejara un
		// disparo espurio pendiente, acá saldrían 3 pasadas antes de tiempo.
		synctest.Sleep(59 * time.Minute)
		synctest.Wait()
		if n := gc.Passes(); n != 2 {
			t.Fatalf("hubo un disparo espurio del temporizador: %d pasadas", n)
		}
		synctest.Sleep(2 * time.Minute)
		synctest.Wait()
		if n := gc.Passes(); n != 3 {
			t.Fatalf("tras NotifyDeletion el loop dejó de reagendar: %d pasadas", n)
		}

		// Y el trabajo real sigue ocurriendo: un upload abandonado se reclama.
		uploadID := seedStaleUpload(t, db)
		synctest.Sleep(25 * time.Hour)
		synctest.Wait()
		if uploadExists(t, db, uploadID) {
			t.Fatal("el GC no reclamó el upload abandonado")
		}
	})
}

// TestScrubberLoop_FirstPassAt30s fija el agendado del scrubber. El
// observable es el cursor por bucket: RunIncremental lo mueve, y hasta que el
// loop no dispara por primera vez no se toca nada.
func TestScrubberLoop_FirstPassAt30s(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db, st := openTestDB(t)
		b := &meta.Bucket{ID: uuid.New().String(), Name: "scrub-loop", Status: "active"}
		if err := db.CreateBucket(b); err != nil {
			t.Fatalf("CreateBucket: %v", err)
		}

		s := NewScrubber(db, st, discardLogger(), time.Hour, 0, 10)
		s.Start()
		t.Cleanup(s.Stop)

		synctest.Sleep(29 * time.Second)
		synctest.Wait()
		if got := s.Coverage().LastFullScan; got != "" {
			t.Fatalf("el scrubber corrió antes de los 30 s (last_full_scan=%q)", got)
		}

		synctest.Sleep(2 * time.Second)
		synctest.Wait()
		// Con un bucket vacío, la primera pasada da la vuelta enseguida y
		// marca el escaneo completo.
		if s.Coverage().LastFullScan == "" {
			t.Fatal("el scrubber no corrió a los 30 s")
		}
	})
}
